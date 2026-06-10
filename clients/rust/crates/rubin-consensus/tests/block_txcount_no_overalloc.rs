//! RUB-449: allocation-bound regression for hostile block `tx_count`.
//!
//! Locks the S003 no-over-allocation invariant: `parse_block_bytes` over a block
//! whose declared `tx_count` is astronomically large (u64::MAX, 2^32, ...) with
//! EOF right after the count must reject it while allocating memory bounded by
//! the INPUT size — never proportional to the attacker-declared count.
//!
//! Metric: the counting allocator below sums the bytes requested by `alloc` and
//! `realloc` growth while armed — cumulative requested bytes, NOT peak in-flight
//! (it never subtracts deallocations). For this invariant that is appropriate
//! and strictly conservative: a count-scaled allocation is caught even if it is
//! freed again before the call returns.
//!
//! The parser already rejects these inputs (RUB-352, PR #1787) and uses
//! `Vec::new()` rather than `Vec::with_capacity(tx_count)`. The existing
//! regression tests assert the error *result* only; they do not assert the
//! *allocation behavior*. A regression to `Vec::with_capacity(tx_count)` (or a
//! capped variant) could pass the error-code tests while re-introducing a
//! sub-crash DoS amplification — this test makes the allocation bound explicit.
//!
//! The counting `#[global_allocator]` below is scoped to THIS integration-test
//! binary only (each `tests/*.rs` file compiles to its own binary), so it does
//! not affect the rest of the suite. Counting is armed only around a single
//! `parse_block_bytes` call, and this binary runs exactly one test, so there is
//! no cross-test race on the shared counters.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rubin_consensus::{parse_block_bytes, BLOCK_HEADER_BYTES};

/// Global allocator that, while ARMED, accumulates the number of bytes
/// requested (fresh allocations and realloc growth). Delegates to `System`.
struct CountingAllocator;

static ARMED: AtomicBool = AtomicBool::new(false);
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Saturating atomic add. A regression that triggers an enormous allocation
/// must never wrap the counter back to a small value that would falsely satisfy
/// the bound below, so accounting saturates at `usize::MAX` instead of wrapping.
fn add_saturating(counter: &AtomicUsize, n: usize) {
    let mut cur = counter.load(Ordering::Relaxed);
    loop {
        let next = cur.saturating_add(n);
        match counter.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => cur = actual,
        }
    }
}

// SAFETY: `CountingAllocator` performs no allocation of its own — every request
// is forwarded verbatim to the `System` allocator with the caller-provided
// layout/pointer, so it upholds exactly the same invariants `System` does. The
// only added work is non-allocating atomic bookkeeping of requested bytes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            add_saturating(&ALLOCATED_BYTES, layout.size());
        }
        // SAFETY: `layout` is forwarded unchanged to the System allocator.
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr`/`layout` come from a prior `System` (re)allocation made
        // through this allocator and are forwarded unchanged.
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) && new_size > layout.size() {
            add_saturating(&ALLOCATED_BYTES, new_size - layout.size());
        }
        // SAFETY: `ptr`/`layout`/`new_size` are forwarded unchanged to System.
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

/// Appends `v` as a *minimally*-encoded CompactSize, matching the consensus
/// `read_compact_size` canonical form (single byte for `< 0xfd`, then `0xfd`+u16
/// / `0xfe`+u32 / `0xff`+u64). Encoding minimally means the parser accepts the
/// count and reaches the tx-list loop for any `count`, instead of rejecting a
/// non-minimal prefix early. Slicing `to_le_bytes()` avoids lossy `as` casts.
fn push_compact_size(buf: &mut Vec<u8>, v: u64) {
    let le = v.to_le_bytes();
    if v < 0xfd {
        buf.push(le[0]);
    } else if v <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&le[..2]);
    } else if v <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&le[..4]);
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&le);
    }
}

/// A block whose declared `tx_count` is `count` (minimally-encoded CompactSize)
/// followed by an immediate EOF — the canonical S003 over-allocation bait.
/// Header bytes are zeroed (mirrors the existing `block_basic_fuzz`
/// construction); the parser reaches the tx-list loop, where any count-scaled
/// allocation would occur, for any valid `count`.
fn block_with_hostile_tx_count(count: u64) -> Vec<u8> {
    let mut buf = vec![0u8; BLOCK_HEADER_BYTES];
    push_compact_size(&mut buf, count);
    buf
}

/// Returns `(rejected, bytes_requested)` for `parse_block_bytes(input)`.
///
/// The counting allocator intercepts allocations process-wide while ARMED, so
/// this measurement relies on there being no *concurrent* allocations during the
/// armed window — which holds because this binary runs a single test on one
/// thread. The input buffer is built by the caller before arming, so its own
/// allocation is not counted.
fn measure_parse(input: &[u8]) -> (bool, usize) {
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let rejected = parse_block_bytes(input).is_err();
    ARMED.store(false, Ordering::Relaxed);
    (rejected, ALLOCATED_BYTES.load(Ordering::Relaxed))
}

/// Generous ceiling: the parser allocates only small bookkeeping buffers plus
/// the error value, never anything scaled to the declared count. A regression to
/// `Vec::with_capacity(tx_count)` would either abort (capacity overflow) or far
/// exceed this. 64 KiB is orders of magnitude below any count-scaled allocation
/// for the counts under test.
const MAX_BOUNDED_ALLOC: usize = 64 * 1024;

#[test]
fn parse_block_bytes_does_not_overallocate_on_hostile_tx_count() {
    // Warm up once (unarmed) so one-time lazy std/runtime initialisation
    // allocations are not attributed to the measured calls.
    let _ = parse_block_bytes(&block_with_hostile_tx_count(1));

    // Positive control: the counting `#[global_allocator]` must actually be
    // active and intercepting. A known heap allocation inside the armed window
    // has to be counted; otherwise a silently-inactive allocator would make the
    // bound below vacuously satisfiable (it would always read 0).
    const CONTROL_BYTES: usize = 50_000;
    let control = {
        ALLOCATED_BYTES.store(0, Ordering::Relaxed);
        ARMED.store(true, Ordering::Relaxed);
        let mut v: Vec<u8> = Vec::with_capacity(CONTROL_BYTES);
        v.push(1);
        std::hint::black_box(&v);
        ARMED.store(false, Ordering::Relaxed);
        ALLOCATED_BYTES.load(Ordering::Relaxed)
    };
    assert!(
        control >= CONTROL_BYTES,
        "counting allocator did not intercept a known {CONTROL_BYTES}-byte allocation \
         (measured {control}); the no-over-allocation bound would be vacuous"
    );

    for count in [u64::MAX, 1u64 << 40, 1u64 << 32] {
        let buf = block_with_hostile_tx_count(count);
        let (rejected, bytes) = measure_parse(&buf);
        assert!(
            rejected,
            "block with tx_count={count} and EOF after the count must be rejected"
        );
        assert!(
            bytes <= MAX_BOUNDED_ALLOC,
            "parse_block_bytes allocated {bytes} bytes for tx_count={count} (input {} bytes); \
             expected <= {MAX_BOUNDED_ALLOC} — allocation must be bounded by input size, \
             never proportional to the declared count",
            buf.len()
        );
    }
}
