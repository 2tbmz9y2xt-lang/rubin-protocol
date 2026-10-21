# Third-party notices and licensing scope

## Rubin-owned material

The root [LICENSE](LICENSE) selects Apache-2.0 for Rubin-owned material that
the licensor is authorized to license, including original code, tooling,
documentation, fixtures and formal source. It does not transfer copyright,
assign ownership, license unresolved third-party rights, or imply affiliation
with the Apache Software Foundation. Third-party material retains its own
licenses, copyright notices and applicable NOTICE obligations. The separate
canonical specification repository and private control plane are outside this
declaration.

Apache-2.0 section 3 grants a patent license only for claims licensable by the
contributing party and necessarily infringed by that party's contribution
alone or in combination with the work to which it was submitted. Patent
licenses for that work terminate when the recipient institutes patent
litigation, including a cross-claim or counterclaim, alleging direct or
contributory infringement by the work or an incorporated contribution, as
specified in section 3. This is not patent clearance or a guarantee against
third-party patent claims, and does not imply that every contributor holds
patents.

Section 5 governs contributions intentionally submitted for inclusion, unless
explicitly stated otherwise, and does not supersede a separate contribution
license agreement. The contribution definition also excludes communications
designated in writing as not a contribution. Neither section 3 nor section 5
retroactively establishes authority over earlier contributions. Section 6
grants no trademark permission beyond reasonable and customary descriptions
of origin and reproduction of NOTICE content. The [official license
text](https://www.apache.org/licenses/LICENSE-2.0.txt) controls.

## Inventory scope and limits

Audit base: `2tbmz9y2xt-lang/rubin-protocol` commit
`5e46979508462c0dc5c18cae0f631766ca35312e`, inspected on 2026-10-21.
The table below is the deduplicated union of external package name/version
pairs in [clients/rust/Cargo.lock](clients/rust/Cargo.lock) and
[clients/rust/fuzz/Cargo.lock](clients/rust/fuzz/Cargo.lock): **103 pairs**.
Different versions of one name have separate rows.

Declared expressions were read from the matching cached Cargo package
manifests. Their cached crate archives matched the lockfile checksums and
contained the same manifests. This establishes the inspected metadata, not
the provenance or licensing of every individual source file. Version-specific
source references below allow inspection of each declaration. The selected
column chooses an available permissive branch without relicensing the
dependency; `AND` requirements remain additive.

This union includes normal, build, development, benchmark, fuzz and
platform-specific dependencies, including targets that are inactive on a
particular host. A lockfile entry does not prove inclusion in any given
binary, and this inventory makes no such claim. The Go client has no external
module requirements; the Go conformance module refers only to the local Go
client. The Node manifests have no dependencies. Bundled libmdbx, pinned
OpenSSL and std4 are listed separately below.

A source checkout that fetches packages externally is distinct from
redistributing their source or binaries. This document is an inventory, not
a binary notice bundle or a complete origin audit. Before any future
redistribution, identify the actual shipped components and include their
required license texts, copyright notices, notices and attributions, including
embedded third-party material. This change does not certify or implement that
future release, package publication, toolchain redistribution or licensing of
another repository.

## Locked external Rust packages

| Package | Version | Declared expression | Selected permissive expression | Version-specific source |
| --- | --- | --- | --- | --- |
| aho-corasick | 1.1.4 | `Unlicense OR MIT` | `MIT` | [manifest](https://docs.rs/crate/aho-corasick/1.1.4/source/Cargo.toml) |
| anes | 0.1.6 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/anes/0.1.6/source/Cargo.toml) |
| anstyle | 1.0.14 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/anstyle/1.0.14/source/Cargo.toml) |
| arbitrary | 1.4.2 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/arbitrary/1.4.2/source/Cargo.toml) |
| autocfg | 1.5.0 | `Apache-2.0 OR MIT` | `MIT` | [manifest](https://docs.rs/crate/autocfg/1.5.0/source/Cargo.toml) |
| bitflags | 2.11.1 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/bitflags/2.11.1/source/Cargo.toml) |
| block-buffer | 0.10.4 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/block-buffer/0.10.4/source/Cargo.toml) |
| block2 | 0.6.2 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/block2/0.6.2/source/Cargo.toml) |
| bumpalo | 3.20.2 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/bumpalo/3.20.2/source/Cargo.toml) |
| cast | 0.3.0 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/cast/0.3.0/source/Cargo.toml) |
| cc | 1.2.56 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/cc/1.2.56/source/Cargo.toml) |
| cc | 1.2.58 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/cc/1.2.58/source/Cargo.toml) |
| cfg-if | 1.0.4 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/cfg-if/1.0.4/source/Cargo.toml) |
| cfg_aliases | 0.2.1 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/cfg_aliases/0.2.1/source/Cargo.toml) |
| ciborium | 0.2.2 | `Apache-2.0` | `Apache-2.0` | [manifest](https://docs.rs/crate/ciborium/0.2.2/source/Cargo.toml) |
| ciborium-io | 0.2.2 | `Apache-2.0` | `Apache-2.0` | [manifest](https://docs.rs/crate/ciborium-io/0.2.2/source/Cargo.toml) |
| ciborium-ll | 0.2.2 | `Apache-2.0` | `Apache-2.0` | [manifest](https://docs.rs/crate/ciborium-ll/0.2.2/source/Cargo.toml) |
| clap | 4.6.0 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/clap/4.6.0/source/Cargo.toml) |
| clap_builder | 4.6.0 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/clap_builder/4.6.0/source/Cargo.toml) |
| clap_lex | 1.1.0 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/clap_lex/1.1.0/source/Cargo.toml) |
| cpufeatures | 0.2.17 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/cpufeatures/0.2.17/source/Cargo.toml) |
| criterion | 0.5.1 | `Apache-2.0 OR MIT` | `MIT` | [manifest](https://docs.rs/crate/criterion/0.5.1/source/Cargo.toml) |
| criterion-plot | 0.5.0 | `MIT/Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/criterion-plot/0.5.0/source/Cargo.toml) |
| crossbeam-deque | 0.8.6 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/crossbeam-deque/0.8.6/source/Cargo.toml) |
| crossbeam-epoch | 0.9.20 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/crossbeam-epoch/0.9.20/source/Cargo.toml) |
| crossbeam-utils | 0.8.21 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/crossbeam-utils/0.8.21/source/Cargo.toml) |
| crunchy | 0.2.4 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/crunchy/0.2.4/source/Cargo.toml) |
| crypto-common | 0.1.7 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/crypto-common/0.1.7/source/Cargo.toml) |
| ctrlc | 3.5.2 | `MIT/Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/ctrlc/3.5.2/source/Cargo.toml) |
| digest | 0.10.7 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/digest/0.10.7/source/Cargo.toml) |
| dispatch2 | 0.3.1 | `Zlib OR Apache-2.0 OR MIT` | `MIT` | [manifest](https://docs.rs/crate/dispatch2/0.3.1/source/Cargo.toml) |
| either | 1.15.0 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/either/1.15.0/source/Cargo.toml) |
| errno | 0.3.14 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/errno/0.3.14/source/Cargo.toml) |
| find-msvc-tools | 0.1.9 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/find-msvc-tools/0.1.9/source/Cargo.toml) |
| generic-array | 0.14.7 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/generic-array/0.14.7/source/Cargo.toml) |
| getrandom | 0.3.4 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/getrandom/0.3.4/source/Cargo.toml) |
| half | 2.7.1 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/half/2.7.1/source/Cargo.toml) |
| hermit-abi | 0.5.2 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/hermit-abi/0.5.2/source/Cargo.toml) |
| hex | 0.4.3 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/hex/0.4.3/source/Cargo.toml) |
| is-terminal | 0.4.17 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/is-terminal/0.4.17/source/Cargo.toml) |
| itertools | 0.10.5 | `MIT/Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/itertools/0.10.5/source/Cargo.toml) |
| itoa | 1.0.17 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/itoa/1.0.17/source/Cargo.toml) |
| itoa | 1.0.18 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/itoa/1.0.18/source/Cargo.toml) |
| jobserver | 0.1.34 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/jobserver/0.1.34/source/Cargo.toml) |
| js-sys | 0.3.92 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/js-sys/0.3.92/source/Cargo.toml) |
| keccak | 0.1.6 | `Apache-2.0 OR MIT` | `MIT` | [manifest](https://docs.rs/crate/keccak/0.1.6/source/Cargo.toml) |
| libc | 0.2.186 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/libc/0.2.186/source/Cargo.toml) |
| libfuzzer-sys | 0.4.12 | `(MIT OR Apache-2.0) AND NCSA` | `MIT AND NCSA` | [manifest](https://docs.rs/crate/libfuzzer-sys/0.4.12/source/Cargo.toml) |
| memchr | 2.8.0 | `Unlicense OR MIT` | `MIT` | [manifest](https://docs.rs/crate/memchr/2.8.0/source/Cargo.toml) |
| nix | 0.31.3 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/nix/0.31.3/source/Cargo.toml) |
| num-bigint | 0.4.6 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/num-bigint/0.4.6/source/Cargo.toml) |
| num-integer | 0.1.46 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/num-integer/0.1.46/source/Cargo.toml) |
| num-traits | 0.2.19 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/num-traits/0.2.19/source/Cargo.toml) |
| objc2 | 0.6.4 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/objc2/0.6.4/source/Cargo.toml) |
| objc2-encode | 4.1.0 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/objc2-encode/4.1.0/source/Cargo.toml) |
| once_cell | 1.21.4 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/once_cell/1.21.4/source/Cargo.toml) |
| oorandom | 11.1.5 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/oorandom/11.1.5/source/Cargo.toml) |
| openssl-sys | 0.9.111 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/openssl-sys/0.9.111/source/Cargo.toml) |
| openssl-sys | 0.9.112 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/openssl-sys/0.9.112/source/Cargo.toml) |
| pkg-config | 0.3.32 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/pkg-config/0.3.32/source/Cargo.toml) |
| plotters | 0.3.7 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/plotters/0.3.7/source/Cargo.toml) |
| plotters-backend | 0.3.7 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/plotters-backend/0.3.7/source/Cargo.toml) |
| plotters-svg | 0.3.7 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/plotters-svg/0.3.7/source/Cargo.toml) |
| proc-macro2 | 1.0.106 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/proc-macro2/1.0.106/source/Cargo.toml) |
| quote | 1.0.44 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/quote/1.0.44/source/Cargo.toml) |
| quote | 1.0.45 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/quote/1.0.45/source/Cargo.toml) |
| r-efi | 5.3.0 | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | `MIT` | [manifest](https://docs.rs/crate/r-efi/5.3.0/source/Cargo.toml) |
| rayon | 1.11.0 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/rayon/1.11.0/source/Cargo.toml) |
| rayon-core | 1.13.0 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/rayon-core/1.13.0/source/Cargo.toml) |
| regex | 1.12.3 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/regex/1.12.3/source/Cargo.toml) |
| regex-automata | 0.4.14 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/regex-automata/0.4.14/source/Cargo.toml) |
| regex-syntax | 0.8.10 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/regex-syntax/0.8.10/source/Cargo.toml) |
| rustversion | 1.0.22 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/rustversion/1.0.22/source/Cargo.toml) |
| same-file | 1.0.6 | `Unlicense/MIT` | `MIT` | [manifest](https://docs.rs/crate/same-file/1.0.6/source/Cargo.toml) |
| serde | 1.0.228 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/serde/1.0.228/source/Cargo.toml) |
| serde_core | 1.0.228 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/serde_core/1.0.228/source/Cargo.toml) |
| serde_derive | 1.0.228 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/serde_derive/1.0.228/source/Cargo.toml) |
| serde_json | 1.0.149 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/serde_json/1.0.149/source/Cargo.toml) |
| sha2 | 0.10.9 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/sha2/0.10.9/source/Cargo.toml) |
| sha3 | 0.10.8 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/sha3/0.10.8/source/Cargo.toml) |
| shlex | 1.3.0 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/shlex/1.3.0/source/Cargo.toml) |
| signal-hook | 0.3.18 | `Apache-2.0/MIT` | `MIT` | [manifest](https://docs.rs/crate/signal-hook/0.3.18/source/Cargo.toml) |
| signal-hook-registry | 1.4.8 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/signal-hook-registry/1.4.8/source/Cargo.toml) |
| syn | 2.0.117 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/syn/2.0.117/source/Cargo.toml) |
| tinytemplate | 1.2.1 | `Apache-2.0 OR MIT` | `MIT` | [manifest](https://docs.rs/crate/tinytemplate/1.2.1/source/Cargo.toml) |
| typenum | 1.19.0 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/typenum/1.19.0/source/Cargo.toml) |
| unicode-ident | 1.0.24 | `(MIT OR Apache-2.0) AND Unicode-3.0` | `MIT AND Unicode-3.0` | [manifest](https://docs.rs/crate/unicode-ident/1.0.24/source/Cargo.toml) |
| vcpkg | 0.2.15 | `MIT/Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/vcpkg/0.2.15/source/Cargo.toml) |
| version_check | 0.9.5 | `MIT/Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/version_check/0.9.5/source/Cargo.toml) |
| walkdir | 2.5.0 | `Unlicense/MIT` | `MIT` | [manifest](https://docs.rs/crate/walkdir/2.5.0/source/Cargo.toml) |
| wasip2 | 1.0.2+wasi-0.2.9 | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `MIT` | [manifest](https://docs.rs/crate/wasip2/1.0.2%2Bwasi-0.2.9/source/Cargo.toml) |
| wasm-bindgen | 0.2.115 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/wasm-bindgen/0.2.115/source/Cargo.toml) |
| wasm-bindgen-macro | 0.2.115 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/wasm-bindgen-macro/0.2.115/source/Cargo.toml) |
| wasm-bindgen-macro-support | 0.2.115 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/wasm-bindgen-macro-support/0.2.115/source/Cargo.toml) |
| wasm-bindgen-shared | 0.2.115 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/wasm-bindgen-shared/0.2.115/source/Cargo.toml) |
| web-sys | 0.3.92 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/web-sys/0.3.92/source/Cargo.toml) |
| winapi-util | 0.1.11 | `Unlicense OR MIT` | `MIT` | [manifest](https://docs.rs/crate/winapi-util/0.1.11/source/Cargo.toml) |
| windows-link | 0.2.1 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/windows-link/0.2.1/source/Cargo.toml) |
| windows-sys | 0.61.2 | `MIT OR Apache-2.0` | `MIT` | [manifest](https://docs.rs/crate/windows-sys/0.61.2/source/Cargo.toml) |
| wit-bindgen | 0.51.0 | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `MIT` | [manifest](https://docs.rs/crate/wit-bindgen/0.51.0/source/Cargo.toml) |
| zerocopy | 0.8.48 | `BSD-2-Clause OR Apache-2.0 OR MIT` | `MIT` | [manifest](https://docs.rs/crate/zerocopy/0.8.48/source/Cargo.toml) |
| zerocopy-derive | 0.8.48 | `BSD-2-Clause OR Apache-2.0 OR MIT` | `MIT` | [manifest](https://docs.rs/crate/zerocopy-derive/0.8.48/source/Cargo.toml) |
| zmij | 1.0.21 | `MIT` | `MIT` | [manifest](https://docs.rs/crate/zmij/1.0.21/source/Cargo.toml) |

### Source-specific terms and legacy expressions

Legacy slash declarations in criterion-plot 0.5.0, ctrlc 3.5.2,
itertools 0.10.5, signal-hook 0.3.18, vcpkg 0.2.15 and version_check 0.9.5
are alternatives between the supplied MIT and Apache-2.0 licenses, not
additive requirements. Their versioned source directories contain both
`LICENSE-MIT` and `LICENSE-APACHE`; the selected MIT branch preserves its
copyright and permission notices. The corresponding source references are
[criterion-plot](https://docs.rs/crate/criterion-plot/0.5.0/source/README.md),
[ctrlc](https://docs.rs/crate/ctrlc/3.5.2/source/README.md),
[itertools](https://docs.rs/crate/itertools/0.10.5/source/README.md),
[signal-hook](https://docs.rs/crate/signal-hook/0.3.18/source/README.md),
[vcpkg licenses](https://docs.rs/crate/vcpkg/0.2.15/source/) and
[version_check](https://docs.rs/crate/version_check/0.9.5/source/README.md).
The `Unlicense/MIT` declarations in
[same-file 1.0.6](https://docs.rs/crate/same-file/1.0.6/source/README.md) and
[walkdir 2.5.0](https://docs.rs/crate/walkdir/2.5.0/source/README.md)
likewise offer alternatives; MIT is selected.

- **unicode-ident 1.0.24:** `MIT AND Unicode-3.0` retains the additional
  Unicode terms. Its [README](https://docs.rs/crate/unicode-ident/1.0.24/source/README.md)
  explains that generated Unicode data requires both licenses.
  [LICENSE-UNICODE](https://docs.rs/crate/unicode-ident/1.0.24/source/LICENSE-UNICODE)
  requires its copyright and permission notice with copies of the data or
  software, or in associated documentation. Keep it as well as the selected
  [MIT license](https://docs.rs/crate/unicode-ident/1.0.24/source/LICENSE-MIT).
- **libfuzzer-sys 0.4.12:** the declared expression and selected
  `MIT AND NCSA` branch retain the additive NCSA requirement. Its
  [README](https://docs.rs/crate/libfuzzer-sys/0.4.12/source/README.md)
  labels the embedded `libfuzzer/` files NCSA, while actual LLVM file headers,
  including [FuzzerDriver.cpp](https://docs.rs/crate/libfuzzer-sys/0.4.12/source/libfuzzer/FuzzerDriver.cpp)
  and [FuzzerDefs.h](https://docs.rs/crate/libfuzzer-sys/0.4.12/source/libfuzzer/FuzzerDefs.h),
  also identify `Apache-2.0 WITH LLVM-exception`. The metadata does not
  exhaust those embedded file terms. Retain the applicable LLVM notices
  and license/exception text, NCSA notices and the selected
  [MIT license](https://docs.rs/crate/libfuzzer-sys/0.4.12/source/LICENSE-MIT)
  when redistributing the corresponding material; resolve actual shipped
  file requirements as part of that redistribution.
- **r-efi 5.3.0:** MIT is selected from
  `MIT OR Apache-2.0 OR LGPL-2.1-or-later`; the LGPL alternative is not selected.
- **cfg_aliases 0.2.1:** keep the embedded MIT attribution in
  [NOTICES.md](https://docs.rs/crate/cfg_aliases/0.2.1/source/NOTICES.md)
  as well as its own MIT license when redistributing relevant material.
- **is-terminal 0.4.17:** keep the derived-atty copyright and permission
  notice in [LICENSE-MIT-atty](https://docs.rs/crate/is-terminal/0.4.17/source/LICENSE-MIT-atty)
  as well as its own MIT license when redistributing relevant material.

## Bundled and separately pinned components

| Component | Exact binding | License and retained source |
| --- | --- | --- |
| libmdbx | 0.14.3; upstream commit `251562b2dc55266d8e6d0e6627ec88ecb410702f` in [VERSION.json](third_party/libmdbx/VERSION.json) | [LICENSE](third_party/libmdbx/LICENSE) declares Apache-2.0; [NOTICE](third_party/libmdbx/NOTICE) and [COPYRIGHT](third_party/libmdbx/COPYRIGHT) retain upstream and historical attribution. The root [NOTICE](NOTICE) reproduces the complete vendored notice. |
| OpenSSL | 3.5.9 in [VERSION](scripts/crypto/openssl/VERSION) | Apache-2.0; the [OpenSSL licensing page](https://openssl-library.org/source/license/index.html) confirms that OpenSSL 3.0 and later use Apache-2.0. The release-specific [source license](https://github.com/openssl/openssl/blob/openssl-3.5.9/LICENSE.txt) is separate from the MIT-licensed openssl-sys 0.9.111 and 0.9.112 Rust bindings above. |
| std4 | `a7543d1a6934d52086971f510e482d743fe30cf3` in [lake-manifest.json](rubin-formal/lake-manifest.json) | Apache-2.0; [license at the pinned revision](https://raw.githubusercontent.com/leanprover/std4/a7543d1a6934d52086971f510e482d743fe30cf3/LICENSE). |

The vendored libmdbx LICENSE, NOTICE and COPYRIGHT remain unchanged,
including their discussion and historical notices. The repository declaration
does not erase or reinterpret those notices.

## Compatibility boundary

No mandatory GPL or AGPL branch was found in the declared 103-pair inventory.
That statement is limited to those declarations and does not certify universal
compatibility. Apache-2.0's GPLv3 compatibility permits inclusion of Apache
material under GPLv3 conditions; it does not authorize relicensing GPLv3
dependencies under Apache-2.0. GPL-2.0-only is not compatible with Apache-2.0.
See the [ASF compatibility explanation](https://www.apache.org/licenses/GPL-compatibility.html);
ASF project distribution policy does not automatically govern Rubin.
