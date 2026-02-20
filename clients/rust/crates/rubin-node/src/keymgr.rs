use std::fs;

use crate::aeskw;

trait KeyWrapProvider {
    fn wrap(&self, kek: &[u8], key_in: &[u8]) -> Result<Vec<u8>, String>;
    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, String>;
}

struct SoftwareKeyWrap;

impl KeyWrapProvider for SoftwareKeyWrap {
    fn wrap(&self, kek: &[u8], key_in: &[u8]) -> Result<Vec<u8>, String> {
        aeskw::aes_key_wrap_rfc3394(kek, key_in)
    }

    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, String> {
        aeskw::aes_key_unwrap_rfc3394(kek, wrapped)
    }
}

#[cfg(feature = "wolfcrypt-dylib")]
struct ShimKeyWrap {
    p: rubin_crypto::WolfcryptDylibProvider,
}

#[cfg(feature = "wolfcrypt-dylib")]
impl KeyWrapProvider for ShimKeyWrap {
    fn wrap(&self, kek: &[u8], key_in: &[u8]) -> Result<Vec<u8>, String> {
        self.p.key_wrap(kek, key_in)
    }

    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, String> {
        self.p.key_unwrap(kek, wrapped).map_err(|e| e.to_string())
    }
}

fn parse_hex_flag(args: &[String], flag: &str) -> Result<Vec<u8>, i32> {
    match crate::get_flag(args, flag) {
        Ok(Some(v)) => match rubin_consensus::hex_decode_strict(&v) {
            Ok(b) => Ok(b),
            Err(e) => {
                eprintln!("{flag}: {e}");
                Err(2)
            }
        },
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

fn parse_opt_hex_flag(args: &[String], flag: &str) -> Result<Option<Vec<u8>>, i32> {
    match crate::get_flag(args, flag) {
        Ok(Some(v)) => match rubin_consensus::hex_decode_strict(&v) {
            Ok(b) => Ok(Some(b)),
            Err(e) => {
                eprintln!("{flag}: {e}");
                Err(2)
            }
        },
        Ok(None) => Ok(None),
        Err(e) => {
            eprintln!("{e}");
            Err(2)
        }
    }
}

fn parse_u8_flag(args: &[String], flag: &str) -> Result<u8, i32> {
    match crate::get_flag(args, flag) {
        Ok(Some(v)) => {
            let s = v.trim();
            let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u8::from_str_radix(hex, 16)
            } else {
                s.parse::<u8>()
            };
            parsed.map_err(|e| {
                eprintln!("{flag}: {e}");
                2
            })
        }
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

fn parse_string_flag(args: &[String], flag: &str) -> Result<String, i32> {
    match crate::get_flag(args, flag) {
        Ok(Some(v)) => Ok(v),
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

fn write_file_0600(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| format!("write {path}: {e}"))?;
    f.write_all(bytes)
        .map_err(|e| format!("write {path}: {e}"))?;
    Ok(())
}

#[cfg(feature = "wolfcrypt-dylib")]
fn load_key_wrapper(strict: bool) -> Result<Box<dyn KeyWrapProvider>, String> {
    let has_shim_path = std::env::var("RUBIN_WOLFCRYPT_SHIM_PATH")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    if !has_shim_path {
        if strict {
            return Err("RUBIN_WOLFCRYPT_STRICT=1 requires RUBIN_WOLFCRYPT_SHIM_PATH".into());
        }
        return Ok(Box::new(SoftwareKeyWrap));
    }

    let p = rubin_crypto::WolfcryptDylibProvider::load_from_env()?;
    if p.has_key_management() {
        Ok(Box::new(ShimKeyWrap { p }))
    } else if strict {
        Err("keymgr requires wolfcrypt shim keywrap symbols in strict mode".into())
    } else {
        Ok(Box::new(SoftwareKeyWrap))
    }
}

#[cfg(not(feature = "wolfcrypt-dylib"))]
fn load_key_wrapper(strict: bool) -> Result<Box<dyn KeyWrapProvider>, String> {
    if strict {
        return Err("RUBIN_WOLFCRYPT_STRICT=1 requires feature wolfcrypt-dylib".into());
    }
    Ok(Box::new(SoftwareKeyWrap))
}

fn read_keystore(path: &str) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read keystore: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("keystore json: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| "keystore json: root must be object".to_string())?;

    let version = obj.get("version").and_then(|v| v.as_str()).unwrap_or("");
    if version != "RBKSv1" {
        return Err(format!("unsupported keystore version: {version:?}"));
    }
    let wrap_alg = obj.get("wrap_alg").and_then(|v| v.as_str()).unwrap_or("");
    if !wrap_alg.eq_ignore_ascii_case("AES-256-KW") {
        return Err(format!("unsupported wrap_alg: {wrap_alg:?}"));
    }
    Ok(obj.clone())
}

fn cmd_keymgr_export_wrapped(args: &[String]) -> i32 {
    let out = match parse_string_flag(args, "--out") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let suite_id = match parse_u8_flag(args, "--suite-id") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let pubkey = match parse_hex_flag(args, "--pubkey-hex") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let sk = match parse_hex_flag(args, "--sk-hex") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let kek = match parse_hex_flag(args, "--kek-hex") {
        Ok(v) => v,
        Err(code) => return code,
    };
    if kek.len() != 32 {
        eprintln!("kek must be 32 bytes (got {})", kek.len());
        return 2;
    }
    if sk.is_empty() || sk.len() % 8 != 0 {
        eprintln!("sk must be non-zero multiple of 8 bytes (AES-KW requirement)");
        return 2;
    }

    let strict = crate::wolfcrypt_strict();
    let km = match load_key_wrapper(strict) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };

    // key_id = SHA3-256(pubkey)
    let provider = match crate::load_crypto_provider() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let key_id = match provider.sha3_256(&pubkey) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };

    let wrapped = match km.wrap(&kek, &sk) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };

    let mut obj = serde_json::Map::new();
    obj.insert(
        "version".to_string(),
        serde_json::Value::String("RBKSv1".to_string()),
    );
    obj.insert(
        "suite_id".to_string(),
        serde_json::Value::Number(serde_json::Number::from(suite_id)),
    );
    obj.insert(
        "pubkey_hex".to_string(),
        serde_json::Value::String(crate::hex_encode(&pubkey)),
    );
    obj.insert(
        "key_id_hex".to_string(),
        serde_json::Value::String(crate::hex_encode(&key_id)),
    );
    obj.insert(
        "wrap_alg".to_string(),
        serde_json::Value::String("AES-256-KW".to_string()),
    );
    obj.insert(
        "wrapped_sk_hex".to_string(),
        serde_json::Value::String(crate::hex_encode(&wrapped)),
    );

    let mut bytes = serde_json::to_vec(&serde_json::Value::Object(obj))
        .map_err(|e| format!("json: {e}"))
        .unwrap();
    bytes.push(b'\n');
    if let Err(e) = write_file_0600(&out, &bytes) {
        eprintln!("{e}");
        return 1;
    }
    0
}

fn cmd_keymgr_import_wrapped(args: &[String]) -> i32 {
    let in_path = match parse_string_flag(args, "--in") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let out_path = match parse_string_flag(args, "--out") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let old_kek = match parse_hex_flag(args, "--old-kek-hex") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let new_kek = match parse_hex_flag(args, "--new-kek-hex") {
        Ok(v) => v,
        Err(code) => return code,
    };
    if old_kek.len() != 32 {
        eprintln!("old-kek must be 32 bytes (got {})", old_kek.len());
        return 2;
    }
    if new_kek.len() != 32 {
        eprintln!("new-kek must be 32 bytes (got {})", new_kek.len());
        return 2;
    }

    let strict = crate::wolfcrypt_strict();
    let km = match load_key_wrapper(strict) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };

    let mut ks = match read_keystore(&in_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let wrapped_sk_hex = ks
        .get("wrapped_sk_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let wrapped = match rubin_consensus::hex_decode_strict(wrapped_sk_hex) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("wrapped_sk_hex: {e}");
            return 1;
        }
    };

    let plain = match km.unwrap(&old_kek, &wrapped) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let new_wrapped = match km.wrap(&new_kek, &plain) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    ks.insert(
        "wrapped_sk_hex".to_string(),
        serde_json::Value::String(crate::hex_encode(&new_wrapped)),
    );

    let mut bytes = serde_json::to_vec(&serde_json::Value::Object(ks))
        .map_err(|e| format!("json: {e}"))
        .unwrap();
    bytes.push(b'\n');
    if let Err(e) = write_file_0600(&out_path, &bytes) {
        eprintln!("{e}");
        return 1;
    }
    0
}

fn cmd_keymgr_verify_pubkey(args: &[String]) -> i32 {
    let in_path = match parse_string_flag(args, "--in") {
        Ok(v) => v,
        Err(code) => return code,
    };
    let expected = match parse_opt_hex_flag(args, "--expected-key-id-hex") {
        Ok(v) => v,
        Err(code) => return code,
    };

    let ks = match read_keystore(&in_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let pubkey_hex = ks.get("pubkey_hex").and_then(|v| v.as_str()).unwrap_or("");
    let pubkey = match rubin_consensus::hex_decode_strict(pubkey_hex) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("pubkey_hex: {e}");
            return 1;
        }
    };

    let provider = match crate::load_crypto_provider() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let key_id = match provider.sha3_256(&pubkey) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let got_hex = crate::hex_encode(&key_id);

    if let Some(embedded) = ks.get("key_id_hex").and_then(|v| v.as_str())
        && !embedded.is_empty()
        && embedded.to_ascii_lowercase() != got_hex
    {
        eprintln!("keystore key_id mismatch: embedded={embedded} computed={got_hex}");
        return 1;
    }
    if let Some(exp) = expected {
        if exp.len() != 32 {
            eprintln!(
                "--expected-key-id-hex must decode to 32 bytes (got {})",
                exp.len()
            );
            return 2;
        }
        let exp_hex = crate::hex_encode(&exp);
        if exp_hex != got_hex {
            eprintln!("expected key_id mismatch: expected={exp_hex} computed={got_hex}");
            return 1;
        }
    }

    println!("{got_hex}");
    0
}

pub fn cmd_keymgr_main(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: rubin-node keymgr <subcommand> [flags]");
        return 2;
    }
    let sub = args[0].as_str();
    let sub_args = &args[1..];
    match sub {
        "export-wrapped" => {
            let rc = cmd_keymgr_export_wrapped(sub_args);
            if rc == 0 {
                println!("OK");
            } else if rc == 1 {
                eprintln!("keymgr export-wrapped error");
            }
            rc
        }
        "import-wrapped" => {
            let rc = cmd_keymgr_import_wrapped(sub_args);
            if rc == 0 {
                println!("OK");
            } else if rc == 1 {
                eprintln!("keymgr import-wrapped error");
            }
            rc
        }
        "verify-pubkey" => cmd_keymgr_verify_pubkey(sub_args),
        _ => {
            eprintln!("unknown keymgr subcommand");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keymgr_verify_pubkey_minimal_keystore() {
        let td = tempfile::tempdir().unwrap();
        let ks_path = td.path().join("k.json");

        // Minimal keystore, no wrapped key needed for verify-pubkey.
        // wrapped_sk_hex may be junk, but verify-pubkey must not crash.
        write_file_0600(
            ks_path.to_str().unwrap(),
            br#"{
  "version": "RBKSv1",
  "suite_id": 1,
  "pubkey_hex": "11",
  "key_id_hex": "",
  "wrap_alg": "AES-256-KW",
  "wrapped_sk_hex": "00"
}
"#,
        )
        .unwrap();

        let rc = cmd_keymgr_verify_pubkey(&vec![
            "--in".to_string(),
            ks_path.to_str().unwrap().to_string(),
        ]);
        assert_eq!(rc, 0);
    }
}
