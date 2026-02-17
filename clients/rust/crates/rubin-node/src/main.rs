use std::fs;
use std::path::{Component, Path};

use rubin_crypto::CryptoProvider;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn extract_fenced_hex(doc: &str, key: &str) -> Result<String, String> {
    let idx = doc
        .find(key)
        .ok_or_else(|| format!("missing key: {key}"))?;
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
            return Ok(Box::new(rubin_crypto::WolfcryptDylibProvider::load_from_env()?));
        }
        #[cfg(not(feature = "wolfcrypt-dylib"))]
        {
            return Err("RUBIN_WOLFCRYPT_STRICT=1 requires feature wolfcrypt-dylib".into());
        }
    }

    #[cfg(feature = "wolfcrypt-dylib")]
    {
        if has_shim_path {
            return Ok(Box::new(rubin_crypto::WolfcryptDylibProvider::load_from_env()?));
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

fn cmd_sighash(chain_id: [u8; 32], tx_hex: &str, input_index: u32, input_value: u64) -> Result<(), String> {
    let tx_bytes = rubin_consensus::hex_decode_strict(tx_hex)?;
    let tx = rubin_consensus::parse_tx_bytes(&tx_bytes)?;
    let provider = load_crypto_provider()?;
    let digest = rubin_consensus::sighash_v1_digest(provider.as_ref(), &chain_id, &tx, input_index, input_value)?;
    println!("{}", hex_encode(&digest));
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

fn usage() {
    eprintln!("usage: rubin-node <command> [args]");
    eprintln!("commands:");
    eprintln!("  version");
    eprintln!("  chain-id --profile <path>");
    eprintln!("  txid --tx-hex <hex>");
    eprintln!("  sighash --tx-hex <hex> --input-index <u32> --input-value <u64> [--chain-id-hex <hex64> | --profile <path>]");
}

fn cmd_version() -> i32 {
    println!("rubin-node (rust) {}", rubin_consensus::CONSENSUS_REVISION);
    0
}

fn cmd_chain_id_main(args: &[String]) -> i32 {
    let profile = match get_flag(args, "--profile") {
        Ok(Some(v)) => v,
        Ok(None) => "spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md".to_string(),
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
        let profile =
            profile.unwrap_or_else(|| "spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md".to_string());
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
        "sighash" => cmd_sighash_main(args),
        _ => {
            eprintln!("unknown command: {cmd}");
            2
        }
    }
}

fn main() {
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
