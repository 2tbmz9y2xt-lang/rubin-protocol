use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path};

use rubin_crypto::CryptoProvider;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn extract_fenced_hex(doc: &str, key: &str) -> Result<String, String> {
    // Preferred format in chain-instance profiles is an inline backticked value:
    // - `genesis_header_bytes`: `...hex...`
    for line in doc.lines() {
        if !line.contains(key) {
            continue;
        }
        let Some(colon) = line.find(':') else {
            continue;
        };
        let after = &line[colon + 1..];
        let Some(first) = after.find('`') else {
            continue;
        };
        let after_first = &after[first + 1..];
        let Some(second) = after_first.find('`') else {
            continue;
        };
        let value = after_first[..second].trim();
        if !value.is_empty() {
            return Ok(value.to_string());
        }
    }

    // Legacy fallback: fenced code block after the key.
    let idx = doc.find(key).ok_or_else(|| format!("missing key: {key}"))?;
    let after = &doc[idx..];
    let fence = after
        .find("```")
        .ok_or_else(|| format!("missing code fence after: {key}"))?;
    let rest = &after[fence + 3..];
    let end = rest
        .find("```")
        .ok_or_else(|| format!("unterminated code fence after: {key}"))?;
    Ok(rest[..end].trim().to_string())
}

fn wolfcrypt_strict() -> bool {
    std::env::var("RUBIN_WOLFCRYPT_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

const DEFAULT_CHAIN_PROFILE: &str = "spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md";

fn load_crypto_provider() -> Result<Box<dyn CryptoProvider>, String> {
    let strict = wolfcrypt_strict();

    #[cfg(feature = "wolfcrypt-dylib")]
    let has_shim_path = std::env::var("RUBIN_WOLFCRYPT_SHIM_PATH")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    if strict {
        #[cfg(feature = "wolfcrypt-dylib")]
        {
            if !has_shim_path {
                return Err("RUBIN_WOLFCRYPT_STRICT=1 requires RUBIN_WOLFCRYPT_SHIM_PATH".into());
            }
            return Ok(Box::new(
                rubin_crypto::WolfcryptDylibProvider::load_from_env()?,
            ));
        }
        #[cfg(not(feature = "wolfcrypt-dylib"))]
        {
            return Err("RUBIN_WOLFCRYPT_STRICT=1 requires feature wolfcrypt-dylib".into());
        }
    }

    #[cfg(feature = "wolfcrypt-dylib")]
    {
        if has_shim_path {
            return Ok(Box::new(
                rubin_crypto::WolfcryptDylibProvider::load_from_env()?,
            ));
        }
    }

    #[cfg(feature = "dev-std")]
    {
        return Ok(Box::new(rubin_crypto::DevStdCryptoProvider));
    }
    #[cfg(not(feature = "dev-std"))]
    {
        Err("no crypto provider available (enable dev-std or wolfcrypt-dylib)".into())
    }
}

fn resolve_profile_path(profile_path: &str) -> Result<String, String> {
    let path = Path::new(profile_path);
    if path.is_absolute() {
        return Err("profile path must be relative".to_string());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("profile path may not escape repository".to_string());
    }

    let root = Path::new("spec");
    let abs_root = root
        .canonicalize()
        .map_err(|e| format!("resolve profile root: {e}"))?;
    let abs_profile = path
        .canonicalize()
        .map_err(|e| format!("resolve profile path: {e}"))?;
    if !abs_profile.starts_with(&abs_root) {
        return Err(format!("profile path must be inside {}", root.display()));
    }

    abs_profile
        .to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "profile path is not valid UTF-8".to_string())
}

fn derive_chain_id(provider: &dyn CryptoProvider, profile_path: &str) -> Result<[u8; 32], String> {
    let safe_profile = resolve_profile_path(profile_path)?;
    let doc = fs::read_to_string(&safe_profile).map_err(|e| format!("read profile: {e}"))?;
    let header_hex = extract_fenced_hex(&doc, "genesis_header_bytes")?;
    let tx_hex = extract_fenced_hex(&doc, "genesis_tx_bytes")?;

    let header_bytes = rubin_consensus::hex_decode_strict(&header_hex)?;
    let tx_bytes = rubin_consensus::hex_decode_strict(&tx_hex)?;

    // serialized_genesis_without_chain_id_field =
    //   ASCII("RUBIN-GENESIS-v1") || genesis_header_bytes || CompactSize(1) || genesis_tx_bytes
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"RUBIN-GENESIS-v1");
    preimage.extend_from_slice(&header_bytes);
    preimage.extend_from_slice(&rubin_consensus::compact_size_encode(1));
    preimage.extend_from_slice(&tx_bytes);

    Ok(provider.sha3_256(&preimage)?)
}

fn cmd_chain_id(profile_path: &str) -> Result<(), String> {
    let provider = load_crypto_provider()?;
    let chain_id = derive_chain_id(provider.as_ref(), profile_path)?;
    println!("{}", hex_encode(&chain_id));
    Ok(())
}

fn cmd_txid(tx_hex: &str) -> Result<(), String> {
    let tx_bytes = rubin_consensus::hex_decode_strict(tx_hex)?;
    let tx = rubin_consensus::parse_tx_bytes(&tx_bytes)?;
    let provider = load_crypto_provider()?;
    let txid = rubin_consensus::txid(provider.as_ref(), &tx)?;
    println!("{}", hex_encode(&txid));
    Ok(())
}

fn parse_chain_id_hex(chain_id_hex: &str) -> Result<[u8; 32], String> {
    let bytes = rubin_consensus::hex_decode_strict(chain_id_hex)?;
    if bytes.len() != 32 {
        return Err(format!(
            "--chain-id-hex must decode to 32 bytes (got {})",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_u16_flag(args: &[String], flag: &str) -> Result<u16, i32> {
    match get_flag(args, flag) {
        Ok(Some(v)) => v.parse::<u16>().map_err(|e| {
            eprintln!("{flag}: {e}");
            2
        }),
        Ok(None) => {
            eprintln!("missing required flag: {flag}");
            Err(2)
        }
        Err(e) => {
            eprintln!("{e}");
            Err(2)
        }
    }
}

fn cmd_sighash(
    chain_id: [u8; 32],
    tx_hex: &str,
    input_index: u32,
    input_value: u64,
) -> Result<(), String> {
    let tx_bytes = rubin_consensus::hex_decode_strict(tx_hex)?;
    let tx = rubin_consensus::parse_tx_bytes(&tx_bytes)?;
    let provider = load_crypto_provider()?;
    let digest = rubin_consensus::sighash_v1_digest(
        provider.as_ref(),
        &chain_id,
        &tx,
        input_index,
        input_value,
    )?;
    println!("{}", hex_encode(&digest));
    Ok(())
}

fn cmd_verify(
    chain_id: [u8; 32],
    tx_hex: &str,
    input_index: u32,
    input_value: u64,
    prevout_covenant_type: u16,
    prevout_covenant_data: Vec<u8>,
    prevout_creation_height: u64,
    chain_height: u64,
    chain_timestamp: u64,
    suite_id_02_active: bool,
) -> Result<(), String> {
    let tx_bytes = rubin_consensus::hex_decode_strict(tx_hex)?;
    let tx = rubin_consensus::parse_tx_bytes(&tx_bytes)?;
    let provider = load_crypto_provider()?;
    let prevout = rubin_consensus::TxOutput {
        value: input_value,
        covenant_type: prevout_covenant_type,
        covenant_data: prevout_covenant_data,
    };
    rubin_consensus::validate_input_authorization(
        provider.as_ref(),
        &chain_id,
        &tx,
        input_index as usize,
        input_value,
        &prevout,
        prevout_creation_height,
        chain_height,
        chain_timestamp,
        suite_id_02_active,
    )?;
    println!("OK");
    Ok(())
}

fn cmd_compactsize(encoded_hex: &str) -> Result<(), String> {
    let bytes = rubin_consensus::hex_decode_strict(encoded_hex)?;
    let (value, _) = rubin_consensus::compact_size_decode(&bytes)?;
    println!("{value}");
    Ok(())
}

fn map_parse_error(err: &str) -> String {
    if err.contains("compactsize:") || err.starts_with("parse:") {
        return "TX_ERR_PARSE".to_string();
    }
    err.to_string()
}

fn cmd_parse(tx_hex: &str, max_witness_bytes: Option<u64>) -> Result<(), String> {
    let tx_bytes = rubin_consensus::hex_decode_strict(tx_hex)?;
    let tx = match rubin_consensus::parse_tx_bytes(&tx_bytes) {
        Ok(v) => v,
        Err(e) => return Err(map_parse_error(&e).to_string()),
    };

    if let Some(max_witness_bytes) = max_witness_bytes {
        let max_witness_bytes = usize::try_from(max_witness_bytes)
            .map_err(|_| format!("invalid --max-witness-bytes {max_witness_bytes}"))?;
        if max_witness_bytes > 0 {
            let witness_bytes = rubin_consensus::witness_bytes(&tx.witness);
            if witness_bytes.len() > max_witness_bytes {
                return Err("TX_ERR_WITNESS_OVERFLOW".to_string());
            }
        }
    }

    println!("OK");
    Ok(())
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let bytes = rubin_consensus::hex_decode_strict(s)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes for txid, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_block_header_bytes_strict(bytes: &[u8]) -> Result<rubin_consensus::BlockHeader, String> {
    if bytes.len() != 4 + 32 + 32 + 8 + 32 + 8 {
        return Err(format!(
            "block-header-bytes: expected 116 bytes, got {}",
            bytes.len()
        ));
    }
    let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let mut prev_block_hash = [0u8; 32];
    prev_block_hash.copy_from_slice(&bytes[4..36]);
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&bytes[36..68]);
    let timestamp = u64::from_le_bytes(bytes[68..76].try_into().unwrap());
    let mut target = [0u8; 32];
    target.copy_from_slice(&bytes[76..108]);
    let nonce = u64::from_le_bytes(bytes[108..116].try_into().unwrap());
    Ok(rubin_consensus::BlockHeader {
        version,
        prev_block_hash,
        merkle_root,
        timestamp,
        target,
        nonce,
    })
}

fn cmd_apply_utxo(context_path: &str) -> Result<(), String> {
    let raw = fs::read_to_string(context_path).map_err(|e| format!("context-json: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("context-json: {e}"))?;

    let tx_hex = v
        .get("tx_hex")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "missing required field: tx_hex".to_string())?;
    let chain_height = v
        .get("chain_height")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let chain_timestamp = v
        .get("chain_timestamp")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let suite_id_02_active = v
        .get("suite_id_02_active")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let tx_bytes = rubin_consensus::hex_decode_strict(tx_hex)?;
    let tx = rubin_consensus::parse_tx_bytes(&tx_bytes)?;
    let provider = load_crypto_provider()?;

    let chain_id = match (
        v.get("chain_id_hex").and_then(|value| value.as_str()),
        v.get("profile").and_then(|value| value.as_str()),
    ) {
        (Some(_), Some(_)) => return Err("use exactly one of chain_id_hex or profile".to_string()),
        (Some(chain_id_hex), None) => parse_chain_id_hex(chain_id_hex)?,
        (None, Some(profile)) => derive_chain_id(provider.as_ref(), profile)?,
        (None, None) => derive_chain_id(provider.as_ref(), DEFAULT_CHAIN_PROFILE)?,
    };

    let mut utxo = HashMap::new();
    if let Some(entries) = v.get("utxo_set").and_then(|value| value.as_array()) {
        for entry in entries {
            let txid_str = entry
                .get("txid")
                .and_then(|value| value.as_str())
                .ok_or_else(|| "utxo_set entry missing txid".to_string())?;
            let vout = entry
                .get("vout")
                .and_then(|value| value.as_u64())
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| "utxo_set entry missing vout".to_string())?;
            let value = entry
                .get("value")
                .and_then(|value| value.as_u64())
                .ok_or_else(|| "utxo_set entry missing value".to_string())?;
            let covenant_type = entry
                .get("covenant_type")
                .and_then(|value| value.as_u64())
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| "utxo_set entry missing covenant_type".to_string())?;
            let covenant_data_hex = entry
                .get("covenant_data")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let covenant_data = if covenant_data_hex.is_empty() {
                Vec::new()
            } else {
                rubin_consensus::hex_decode_strict(covenant_data_hex)?
            };
            let creation_height = entry
                .get("creation_height")
                .and_then(|value| value.as_u64())
                .unwrap_or(chain_height);
            let created_by_coinbase = entry
                .get("created_by_coinbase")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);

            utxo.insert(
                rubin_consensus::TxOutPoint {
                    txid: parse_hex32(txid_str)?,
                    vout,
                },
                rubin_consensus::UtxoEntry {
                    output: rubin_consensus::TxOutput {
                        value,
                        covenant_type,
                        covenant_data,
                    },
                    creation_height,
                    created_by_coinbase,
                },
            );
        }
    }

    rubin_consensus::apply_tx(
        provider.as_ref(),
        &chain_id,
        &tx,
        &utxo,
        chain_height,
        chain_timestamp,
        suite_id_02_active,
    )?;
    Ok(())
}

fn cmd_apply_block(context_path: &str) -> Result<(), String> {
    let raw = fs::read_to_string(context_path).map_err(|e| format!("context-json: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("context-json: {e}"))?;

    let block_hex = v
        .get("block_hex")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "missing required field: block_hex".to_string())?;
    let block_height = v
        .get("block_height")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let local_time = v.get("local_time").and_then(|value| value.as_u64()).unwrap_or(0);
    let local_time_set = v
        .get("local_time_set")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let suite_id_02_active = v
        .get("suite_id_02_active")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let block_bytes = rubin_consensus::hex_decode_strict(block_hex)?;
    let block = rubin_consensus::parse_block_bytes(&block_bytes)?;
    let provider = load_crypto_provider()?;

    let chain_id = match (
        v.get("chain_id_hex").and_then(|value| value.as_str()),
        v.get("profile").and_then(|value| value.as_str()),
    ) {
        (Some(_), Some(_)) => return Err("use exactly one of chain_id_hex or profile".to_string()),
        (Some(chain_id_hex), None) => parse_chain_id_hex(chain_id_hex)?,
        (None, Some(profile)) => derive_chain_id(provider.as_ref(), profile)?,
        (None, None) => derive_chain_id(provider.as_ref(), DEFAULT_CHAIN_PROFILE)?,
    };

    let mut ancestors = Vec::new();
    if let Some(entries) = v
        .get("ancestor_headers_hex")
        .and_then(|value| value.as_array())
    {
        for entry in entries {
            let hx = entry
                .as_str()
                .ok_or_else(|| "ancestor_headers_hex entry must be string".to_string())?;
            let hb = rubin_consensus::hex_decode_strict(hx)?;
            ancestors.push(parse_block_header_bytes_strict(&hb)?);
        }
    }

    let mut utxo = HashMap::new();
    if let Some(entries) = v.get("utxo_set").and_then(|value| value.as_array()) {
        for entry in entries {
            let txid_str = entry
                .get("txid")
                .and_then(|value| value.as_str())
                .ok_or_else(|| "utxo_set entry missing txid".to_string())?;
            let vout = entry
                .get("vout")
                .and_then(|value| value.as_u64())
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| "utxo_set entry missing vout".to_string())?;
            let value = entry
                .get("value")
                .and_then(|value| value.as_u64())
                .ok_or_else(|| "utxo_set entry missing value".to_string())?;
            let covenant_type = entry
                .get("covenant_type")
                .and_then(|value| value.as_u64())
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| "utxo_set entry missing covenant_type".to_string())?;
            let covenant_data_hex = entry
                .get("covenant_data")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let covenant_data = if covenant_data_hex.is_empty() {
                Vec::new()
            } else {
                rubin_consensus::hex_decode_strict(covenant_data_hex)?
            };
            let creation_height = entry
                .get("creation_height")
                .and_then(|value| value.as_u64())
                .unwrap_or(block_height);
            let created_by_coinbase = entry
                .get("created_by_coinbase")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);

            utxo.insert(
                rubin_consensus::TxOutPoint {
                    txid: parse_hex32(txid_str)?,
                    vout,
                },
                rubin_consensus::UtxoEntry {
                    output: rubin_consensus::TxOutput {
                        value,
                        covenant_type,
                        covenant_data,
                    },
                    creation_height,
                    created_by_coinbase,
                },
            );
        }
    }

    let ctx = rubin_consensus::BlockValidationContext {
        height: block_height,
        ancestor_headers: ancestors,
        local_time,
        local_time_set,
        suite_id_02_active,
    };

    rubin_consensus::apply_block(provider.as_ref(), &chain_id, &block, &mut utxo, &ctx)?;
    Ok(())
}

fn get_flag(args: &[String], flag: &str) -> Result<Option<String>, String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if i + 1 >= args.len() {
                return Err(format!("missing value for {flag}"));
            }
            return Ok(Some(args[i + 1].clone()));
        }
        i += 1;
    }
    Ok(None)
}

fn flag_present(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn usage() {
    eprintln!("usage: rubin-node <command> [args]");
    eprintln!("commands:");
    eprintln!("  version");
    eprintln!("  chain-id --profile <path>");
    eprintln!("  txid --tx-hex <hex>");
    eprintln!("  apply-utxo --context-json <path>");
    eprintln!("  apply-block --context-json <path>");
    eprintln!("  compactsize --encoded-hex <hex>");
    eprintln!("  parse --tx-hex <hex> [--max-witness-bytes <u64>]");
    eprintln!(
        "  sighash --tx-hex <hex> --input-index <u32> --input-value <u64> [--chain-id-hex <hex64> | --profile <path>]"
    );
    eprintln!(
        "  verify --tx-hex <hex> --input-index <u32> --input-value <u64> --prevout-covenant-type <u16> --prevout-covenant-data-hex <hex> [--prevout-creation-height <u64>] [--chain-height <u64> | --chain-timestamp <u64> | --chain-id-hex <hex64> | --profile <path> | --suite-id-02-active]"
    );
}

fn cmd_version() -> i32 {
    println!("rubin-node (rust) {}", rubin_consensus::CONSENSUS_REVISION);
    0
}

fn cmd_chain_id_main(args: &[String]) -> i32 {
    let profile = match get_flag(args, "--profile") {
        Ok(Some(v)) => v,
        Ok(None) => DEFAULT_CHAIN_PROFILE.to_string(),
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    if let Err(e) = cmd_chain_id(&profile) {
        eprintln!("chain-id error: {e}");
        return 1;
    }
    0
}

fn cmd_txid_main(args: &[String]) -> i32 {
    let tx_hex = match get_flag(args, "--tx-hex") {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("missing required flag: --tx-hex");
            return 2;
        }
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    if let Err(e) = cmd_txid(&tx_hex) {
        eprintln!("txid error: {e}");
        return 1;
    }
    0
}

fn parse_required_u32(args: &[String], flag: &str) -> Result<u32, i32> {
    match get_flag(args, flag) {
        Ok(Some(v)) => v.parse::<u32>().map_err(|e| {
            eprintln!("{flag}: {e}");
            2
        }),
        Ok(None) => {
            eprintln!("missing required flag: {flag}");
            Err(2)
        }
        Err(e) => {
            eprintln!("{e}");
            Err(2)
        }
    }
}

fn parse_required_u64(args: &[String], flag: &str) -> Result<u64, i32> {
    match get_flag(args, flag) {
        Ok(Some(v)) => v.parse::<u64>().map_err(|e| {
            eprintln!("{flag}: {e}");
            2
        }),
        Ok(None) => {
            eprintln!("missing required flag: {flag}");
            Err(2)
        }
        Err(e) => {
            eprintln!("{e}");
            Err(2)
        }
    }
}

fn parse_optional_u64(args: &[String], flag: &str) -> Result<Option<u64>, i32> {
    match get_flag(args, flag) {
        Ok(Some(v)) => v
            .parse::<u64>()
            .map_err(|e| {
                eprintln!("{flag}: {e}");
                2
            })
            .map(Some),
        Ok(None) => Ok(None),
        Err(e) => {
            eprintln!("{e}");
            Err(2)
        }
    }
}

fn cmd_parse_main(args: &[String]) -> i32 {
    let tx_hex = match get_flag(args, "--tx-hex") {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("missing required flag: --tx-hex");
            return 2;
        }
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let max_witness_bytes = match parse_optional_u64(args, "--max-witness-bytes") {
        Ok(v) => v,
        Err(code) => return code,
    };

    if let Err(e) = cmd_parse(&tx_hex, max_witness_bytes) {
        eprintln!("{e}");
        return 1;
    }
    0
}

fn cmd_apply_utxo_main(args: &[String]) -> i32 {
    let context_path = match get_flag(args, "--context-json") {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("missing required flag: --context-json");
            return 2;
        }
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    match cmd_apply_utxo(&context_path) {
        Ok(()) => {
            println!("OK");
            0
        }
        Err(e) => {
            eprintln!("apply-utxo error: {e}");
            1
        }
    }
}

fn cmd_apply_block_main(args: &[String]) -> i32 {
    let context_path = match get_flag(args, "--context-json") {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("missing required flag: --context-json");
            return 2;
        }
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    match cmd_apply_block(&context_path) {
        Ok(()) => {
            println!("OK");
            0
        }
        Err(e) => {
            eprintln!("apply-block error: {e}");
            1
        }
    }
}

fn cmd_verify_main(args: &[String]) -> i32 {
    let tx_hex = match get_flag(args, "--tx-hex") {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("missing required flag: --tx-hex");
            return 2;
        }
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let input_index = match parse_required_u32(args, "--input-index") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let input_value = match parse_required_u64(args, "--input-value") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let prevout_covenant_type = match parse_u16_flag(args, "--prevout-covenant-type") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let prevout_covenant_data = match get_flag(args, "--prevout-covenant-data-hex") {
        Ok(Some(v)) => match rubin_consensus::hex_decode_strict(&v) {
            Ok(decoded) => decoded,
            Err(e) => {
                eprintln!("prevout-covenant-data-hex: {e}");
                return 1;
            }
        },
        Ok(None) => {
            eprintln!("missing required flag: --prevout-covenant-data-hex");
            return 2;
        }
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let chain_id_hex = match get_flag(args, "--chain-id-hex") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let profile = match get_flag(args, "--profile") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    if chain_id_hex.is_some() && profile.is_some() {
        eprintln!("use exactly one of --chain-id-hex or --profile");
        return 2;
    }

    let chain_height = match get_flag(args, "--chain-height") {
        Ok(Some(v)) => match v.parse::<u64>() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("--chain-height: {e}");
                return 2;
            }
        },
        Ok(None) => 0,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let chain_timestamp = match get_flag(args, "--chain-timestamp") {
        Ok(Some(v)) => match v.parse::<u64>() {
            Ok(ts) => ts,
            Err(e) => {
                eprintln!("--chain-timestamp: {e}");
                return 2;
            }
        },
        Ok(None) => 0,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let prevout_creation_height = match get_flag(args, "--prevout-creation-height") {
        Ok(Some(v)) => match v.parse::<u64>() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("--prevout-creation-height: {e}");
                return 2;
            }
        },
        Ok(None) => chain_height,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let suite_id_02_active = flag_present(args, "--suite-id-02-active");

    let chain_id = if let Some(hex) = chain_id_hex {
        match parse_chain_id_hex(&hex) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e}");
                return 2;
            }
        }
    } else {
        let profile = profile.unwrap_or_else(|| DEFAULT_CHAIN_PROFILE.to_string());
        let provider = match load_crypto_provider() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{e}");
                return 1;
            }
        };
        match derive_chain_id(provider.as_ref(), &profile) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("verify error: {e}");
                return 1;
            }
        }
    };

    if let Err(e) = cmd_verify(
        chain_id,
        &tx_hex,
        input_index,
        input_value,
        prevout_covenant_type,
        prevout_covenant_data,
        prevout_creation_height,
        chain_height,
        chain_timestamp,
        suite_id_02_active,
    ) {
        eprintln!("verify error: {e}");
        return 1;
    }
    0
}

fn cmd_compactsize_main(args: &[String]) -> i32 {
    let encoded_hex = match get_flag(args, "--encoded-hex") {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("missing required flag: --encoded-hex");
            return 2;
        }
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    if let Err(e) = cmd_compactsize(&encoded_hex) {
        eprintln!("{e}");
        return 1;
    }
    0
}

fn cmd_sighash_main(args: &[String]) -> i32 {
    let tx_hex = match get_flag(args, "--tx-hex") {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("missing required flag: --tx-hex");
            return 2;
        }
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    let input_index = match parse_required_u32(args, "--input-index") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let input_value = match parse_required_u64(args, "--input-value") {
        Ok(v) => v,
        Err(code) => return code,
    };

    let chain_id_hex = match get_flag(args, "--chain-id-hex") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let profile = match get_flag(args, "--profile") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    if chain_id_hex.is_some() && profile.is_some() {
        eprintln!("use exactly one of --chain-id-hex or --profile");
        return 2;
    }

    let chain_id = if let Some(hex) = chain_id_hex {
        match parse_chain_id_hex(&hex) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e}");
                return 2;
            }
        }
    } else {
        let profile = profile.unwrap_or_else(|| DEFAULT_CHAIN_PROFILE.to_string());
        let provider = match load_crypto_provider() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{e}");
                return 1;
            }
        };
        match derive_chain_id(provider.as_ref(), &profile) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("sighash error: {e}");
                return 1;
            }
        }
    };

    if let Err(e) = cmd_sighash(chain_id, &tx_hex, input_index, input_value) {
        eprintln!("sighash error: {e}");
        return 1;
    }
    0
}

fn dispatch(cmd: &str, args: &[String]) -> i32 {
    match cmd {
        "version" => cmd_version(),
        "chain-id" => cmd_chain_id_main(args),
        "txid" => cmd_txid_main(args),
        "parse" => cmd_parse_main(args),
        "apply-utxo" => cmd_apply_utxo_main(args),
        "apply-block" => cmd_apply_block_main(args),
        "compactsize" => cmd_compactsize_main(args),
        "sighash" => cmd_sighash_main(args),
        "verify" => cmd_verify_main(args),
        _ => {
            eprintln!("unknown command: {cmd}");
            2
        }
    }
}

fn main() {
    // nosemgrep: rust.lang.security.args.args
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
        std::process::exit(2);
    }
    let cmd = args.remove(0);
    let exit_code = dispatch(&cmd, &args);
    if exit_code != 0 {
        if exit_code == 2 {
            usage();
        }
        std::process::exit(exit_code);
    }
}
