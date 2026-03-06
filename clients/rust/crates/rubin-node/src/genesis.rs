use std::fs;
use std::path::Path;

use serde::Deserialize;
use rubin_consensus::encode_compact_size;

const GENESIS_HEADER_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000006f732e615e2f43337a53e9884adba7da32257d5bb5701adc7ed0bd406f2df91340e49e6900000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000";
const GENESIS_TX_HEX: &str = "01000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0200407a10f35a0000000021018448b91b88d1a6fbb65e872b72c381b2a9f3ce286a232f56309667f639dd72790000000000000000020020b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a8000000000000";
const GENESIS_CHAIN_ID_HEX: &str =
    "88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103";
#[cfg(test)]
const GENESIS_MAGIC_SEPARATOR: &[u8] = b"RUBIN-GENESIS-v1";

#[derive(Deserialize)]
struct GenesisPack {
    chain_id_hex: String,
}

pub fn devnet_genesis_block_bytes() -> Vec<u8> {
    let header = decode_hex_exact("genesis_header", GENESIS_HEADER_HEX, 116);
    let tx = decode_hex_exact("genesis_tx", GENESIS_TX_HEX, 149);
    let mut out = Vec::with_capacity(header.len() + tx.len() + 8);
    out.extend_from_slice(&header);
    encode_compact_size(1, &mut out);
    out.extend_from_slice(&tx);
    out
}

pub fn devnet_genesis_chain_id() -> [u8; 32] {
    decode_hex32("devnet_genesis_chain_id", GENESIS_CHAIN_ID_HEX)
}

pub fn load_chain_id_from_genesis_file(path: Option<&Path>) -> Result<[u8; 32], String> {
    let Some(path) = path else {
        return Ok(devnet_genesis_chain_id());
    };
    let raw =
        fs::read_to_string(path).map_err(|e| format!("read genesis file {}: {e}", path.display()))?;
    let payload: GenesisPack = serde_json::from_str(&raw)
        .map_err(|e| format!("parse genesis file {}: {e}", path.display()))?;
    let mut trimmed = payload.chain_id_hex.trim();
    if trimmed.is_empty() {
        return Err("chain_id_hex missing".to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("0x") {
        trimmed = rest;
    } else if let Some(rest) = trimmed.strip_prefix("0X") {
        trimmed = rest;
    }
    parse_hex32("chain_id", trimmed)
}

pub fn validate_incoming_chain_id(block_height: u64, chain_id: [u8; 32]) -> Result<(), String> {
    let zero_chain_id = [0u8; 32];
    if block_height == 0 && chain_id != zero_chain_id && chain_id != devnet_genesis_chain_id() {
        return Err("genesis chain_id mismatch".to_string());
    }
    Ok(())
}

#[cfg(test)]
fn derive_devnet_genesis_chain_id() -> [u8; 32] {
    use sha3::{Digest, Sha3_256};

    let header = decode_hex_exact("genesis_header", GENESIS_HEADER_HEX, 116);
    let tx = decode_hex_exact("genesis_tx", GENESIS_TX_HEX, 149);
    let mut preimage = Vec::with_capacity(GENESIS_MAGIC_SEPARATOR.len() + header.len() + tx.len() + 8);
    preimage.extend_from_slice(GENESIS_MAGIC_SEPARATOR);
    preimage.extend_from_slice(&header);
    encode_compact_size(1, &mut preimage);
    preimage.extend_from_slice(&tx);
    Sha3_256::digest(&preimage).into()
}

fn decode_hex32(name: &str, value: &str) -> [u8; 32] {
    parse_hex32(name, value).unwrap_or_else(|e| panic!("{e}"))
}

fn decode_hex_exact(name: &str, value: &str, expected_len: usize) -> Vec<u8> {
    let bytes = hex::decode(value).unwrap_or_else(|e| panic!("{name}: {e}"));
    if bytes.len() != expected_len {
        panic!("{name}: expected {expected_len} bytes, got {}", bytes.len());
    }
    bytes
}

fn parse_hex32(name: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|e| format!("{name}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{name}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        devnet_genesis_block_bytes, devnet_genesis_chain_id, derive_devnet_genesis_chain_id,
        load_chain_id_from_genesis_file, validate_incoming_chain_id,
    };

    #[test]
    fn derived_devnet_chain_id_matches_constant() {
        assert_eq!(derive_devnet_genesis_chain_id(), devnet_genesis_chain_id());
    }

    #[test]
    fn devnet_genesis_block_bytes_have_expected_frame() {
        let block = devnet_genesis_block_bytes();
        assert_eq!(block.len(), 116 + 1 + 149);
        assert_eq!(block[116], 0x01);
    }

    #[test]
    fn load_chain_id_defaults_to_devnet_when_genesis_file_absent() {
        let got = load_chain_id_from_genesis_file(None).expect("default chain_id");
        assert_eq!(got, devnet_genesis_chain_id());
    }

    #[test]
    fn load_chain_id_reads_chain_id_from_json() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\"}",
        )
        .expect("write");

        let got = load_chain_id_from_genesis_file(Some(&path)).expect("load");
        assert_eq!(got, devnet_genesis_chain_id());

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn validate_incoming_chain_id_accepts_zero_chain_id_at_genesis() {
        validate_incoming_chain_id(0, [0u8; 32]).expect("zero chain_id should skip genesis guard");
    }

    #[test]
    fn validate_incoming_chain_id_rejects_wrong_non_zero_genesis_chain_id() {
        let err = validate_incoming_chain_id(0, [0x11; 32]).unwrap_err();
        assert_eq!(err, "genesis chain_id mismatch");
    }
}
