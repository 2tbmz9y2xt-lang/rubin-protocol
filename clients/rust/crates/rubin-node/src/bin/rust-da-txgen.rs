//! Devnet-only signed DA tx source for `scripts/devnet-rust-da-relay.sh`
//! (RUB-442, `Q-RUST-DA-SIGNED-TX-SOURCE-01`).
//!
//! Usage: `rust-da-txgen [--] <datadir> [mine_blocks]`
//!
//! `--` terminates flag parsing so a datadir path beginning with `-` is
//! accepted; unknown `-`-prefixed flags are rejected.
//!
//! Mines a fresh base chain into `<datadir>` paying an ephemeral in-process
//! devnet keypair, then emits a JSON object of signed DA txs
//! (`{da_id, chunk0, commit, duplicate_commit, chunk1: {hex, txid}}`) to stdout.
//! The keypair is generated, used for mining and signing, and discarded within
//! this one process, so no key material crosses a process boundary or touches
//! disk. `mine_blocks` defaults to the matured base height used by the relay
//! smoke.
//!
//! A second mode mirrors the Go helper's `blockcheck` subcommand (RUB-443):
//! `rust-da-txgen blockcheck <block_hex> <block_hash> <tx_count> <required_txids_csv> <forbidden_txids_csv>`
//! parses a canonical block and asserts its hash, tx_count, and txid
//! membership (`-` is the empty-list placeholder, matching the Go harness).

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;

use rubin_consensus::{block_hash, parse_block_bytes};
use rubin_node::da_txgen::{mine_and_generate, DA_RELAY_BASE_HEIGHT};

const PROGRAM: &str = "rust-da-txgen";

fn usage() -> String {
    format!(
        "usage: {PROGRAM} [--] <datadir> [mine_blocks]\n       {PROGRAM} blockcheck <block_hex> <block_hash> <tx_count> <required_txids_csv> <forbidden_txids_csv>"
    )
}

/// Split a Go-harness txid CSV: `-` (or empty) means no entries; entries are
/// trimmed and lowercased.
fn split_txids_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty() && item != "-")
        .collect()
}

/// Mirror of the Go harness `blockcheck` mode: parse the canonical block
/// bytes, assert the header hash and tx_count, and check required/forbidden
/// txid membership.
fn blockcheck(args: &[String]) -> Result<(), String> {
    let [block_hex, want_hash, want_count, required_csv, forbidden_csv] = args else {
        return Err(usage());
    };
    let raw = hex::decode(block_hex.trim()).map_err(|err| format!("block_hex: {err}"))?;
    let pb = parse_block_bytes(&raw).map_err(|err| format!("parse block: {err}"))?;
    let got_hash = block_hash(&pb.header_bytes).map_err(|err| format!("block hash: {err}"))?;
    if hex::encode(got_hash) != want_hash.trim().to_ascii_lowercase() {
        return Err("parsed block hash mismatch".to_string());
    }
    let want_count = want_count
        .parse::<u64>()
        .map_err(|_| format!("invalid tx_count: {want_count}"))?;
    if pb.tx_count != want_count {
        return Err(format!(
            "parsed block tx_count mismatch: got {} want {want_count}",
            pb.tx_count
        ));
    }
    let seen: Vec<String> = pb.txids.iter().map(hex::encode).collect();
    for txid in split_txids_csv(required_csv) {
        if !seen.contains(&txid) {
            return Err(format!("missing txid {txid}"));
        }
    }
    for txid in split_txids_csv(forbidden_csv) {
        if seen.contains(&txid) {
            return Err(format!("unexpected txid {txid}"));
        }
    }
    Ok(())
}

/// Strict positional parse: `-h`/`--help` print usage; any other `-`-prefixed
/// token before `--` is an error rather than being silently dropped; `--`
/// terminates flag parsing so a datadir path beginning with `-` is accepted.
/// Returns the (datadir, mine_blocks) pair, or `Ok(None)` when help was shown.
fn parse_args(args: &[String]) -> Result<Option<(PathBuf, u64)>, String> {
    let mut positional: Vec<&str> = Vec::with_capacity(2);
    let mut flags_done = false;
    for arg in args {
        if flags_done {
            positional.push(arg);
            continue;
        }
        match arg.as_str() {
            "--" => flags_done = true,
            "-h" | "--help" => {
                println!("{}", usage());
                return Ok(None);
            }
            _ if arg.starts_with('-') => return Err(format!("unknown flag {arg}\n{}", usage())),
            _ => positional.push(arg),
        }
    }
    if positional.is_empty() || positional.len() > 2 {
        return Err(usage());
    }
    let datadir = PathBuf::from(positional[0]);
    let mine_blocks = match positional.get(1) {
        Some(value) => value
            .parse::<u64>()
            .map_err(|_| format!("invalid mine_blocks: {value}"))?,
        None => DA_RELAY_BASE_HEIGHT,
    };
    Ok(Some((datadir, mine_blocks)))
}

fn run(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("blockcheck") {
        return blockcheck(&args[1..]);
    }
    let Some((datadir, mine_blocks)) = parse_args(args)? else {
        return Ok(());
    };
    let set = mine_and_generate(&datadir, mine_blocks)?;
    let mut stdout = io::stdout();
    serde_json::to_writer(&mut stdout, &set.to_json())
        .map_err(|err| format!("encode DA txs json: {err}"))?;
    writeln!(stdout).map_err(|err| err.to_string())?;
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if let Err(err) = run(&args) {
        let _ = writeln!(io::stderr(), "{err}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_args, DA_RELAY_BASE_HEIGHT};
    use std::path::PathBuf;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn datadir_only_defaults_mine_blocks() {
        let parsed = parse_args(&args(&["/tmp/dd"])).expect("ok").expect("some");
        assert_eq!(parsed, (PathBuf::from("/tmp/dd"), DA_RELAY_BASE_HEIGHT));
    }

    #[test]
    fn datadir_and_mine_blocks() {
        let parsed = parse_args(&args(&["/tmp/dd", "12"]))
            .expect("ok")
            .expect("some");
        assert_eq!(parsed, (PathBuf::from("/tmp/dd"), 12));
    }

    #[test]
    fn unknown_flag_is_rejected_not_dropped() {
        let err = parse_args(&args(&["--foo", "/tmp/dd"])).expect_err("must reject");
        assert!(err.contains("unknown flag --foo"), "got: {err}");
    }

    #[test]
    fn double_dash_allows_dash_prefixed_datadir() {
        let parsed = parse_args(&args(&["--", "-weird-path"]))
            .expect("ok")
            .expect("some");
        assert_eq!(parsed, (PathBuf::from("-weird-path"), DA_RELAY_BASE_HEIGHT));
    }

    #[test]
    fn help_returns_none() {
        assert!(parse_args(&args(&["--help"])).expect("ok").is_none());
        assert!(parse_args(&args(&["-h"])).expect("ok").is_none());
    }

    #[test]
    fn missing_and_excess_positionals_are_errors() {
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["a", "b", "c"])).is_err());
    }

    #[test]
    fn invalid_mine_blocks_is_an_error() {
        let err = parse_args(&args(&["/tmp/dd", "nope"])).expect_err("must reject");
        assert!(err.contains("invalid mine_blocks"), "got: {err}");
    }

    #[test]
    fn split_txids_csv_handles_placeholder_and_entries() {
        assert!(super::split_txids_csv("-").is_empty());
        assert!(super::split_txids_csv("").is_empty());
        assert_eq!(
            super::split_txids_csv("AB12, cd34 ,-,"),
            vec!["ab12".to_string(), "cd34".to_string()]
        );
    }

    #[test]
    fn blockcheck_rejects_wrong_arity_and_bad_hex() {
        let err = super::blockcheck(&args(&["deadbeef"])).expect_err("arity");
        assert!(err.contains("usage:"), "got: {err}");
        let err = super::blockcheck(&args(&["zz", "0", "1", "-", "-"])).expect_err("bad hex");
        assert!(err.contains("block_hex"), "got: {err}");
        let err =
            super::blockcheck(&args(&["deadbeef", "0", "1", "-", "-"])).expect_err("bad block");
        assert!(err.contains("parse block"), "got: {err}");
    }
}
