use rubin_consensus::constants::{
    COV_TYPE_ANCHOR, COV_TYPE_P2PK, MAX_P2PK_COVENANT_DATA, SUITE_ID_ML_DSA_87,
};
use rubin_consensus::{block_subsidy, encode_compact_size};

const MINE_ADDRESS_KEY_ID_BYTES: usize = 32;

pub fn default_mine_address() -> Vec<u8> {
    let mut out = vec![0u8; MAX_P2PK_COVENANT_DATA as usize];
    out[0] = SUITE_ID_ML_DSA_87;
    out
}

pub fn normalize_mine_address(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.is_empty() {
        return Ok(default_mine_address());
    }
    validate_mine_address(raw)?;
    Ok(raw.to_vec())
}

pub fn validate_mine_address(raw: &[u8]) -> Result<(), String> {
    let expected_len = MAX_P2PK_COVENANT_DATA as usize;
    if raw.len() != expected_len {
        return Err(format!(
            "mine_address: expected {expected_len} bytes, got {}",
            raw.len()
        ));
    }
    if raw[0] != SUITE_ID_ML_DSA_87 {
        return Err(format!(
            "mine_address: unsupported suite_id 0x{:02x}",
            raw[0]
        ));
    }
    Ok(())
}

pub fn parse_mine_address(value: &str) -> Result<Option<Vec<u8>>, String> {
    let mut trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Some(rest) = trimmed.strip_prefix("0x") {
        trimmed = rest;
    } else if let Some(rest) = trimmed.strip_prefix("0X") {
        trimmed = rest;
    }
    if !trimmed.len().is_multiple_of(2) {
        return Err("mine_address: odd-length hex".to_string());
    }
    let raw = hex::decode(trimmed).map_err(|e| format!("mine_address: {e}"))?;
    match raw.len() {
        MINE_ADDRESS_KEY_ID_BYTES => {
            let mut out = Vec::with_capacity(MAX_P2PK_COVENANT_DATA as usize);
            out.push(SUITE_ID_ML_DSA_87);
            out.extend_from_slice(&raw);
            Ok(Some(out))
        }
        n if n == MAX_P2PK_COVENANT_DATA as usize => {
            validate_mine_address(&raw)?;
            Ok(Some(raw))
        }
        got => Err(format!(
            "mine_address: expected {MINE_ADDRESS_KEY_ID_BYTES}-byte key_id or {}-byte covenant_data, got {got} bytes",
            MAX_P2PK_COVENANT_DATA
        )),
    }
}

pub fn build_coinbase_tx(
    height: u64,
    already_generated: u64,
    mine_address: &[u8],
    witness_commitment: [u8; 32],
) -> Result<Vec<u8>, String> {
    if height > u64::from(u32::MAX) {
        return Err("block height exceeds coinbase locktime range".to_string());
    }

    let subsidy = block_subsidy(height, u128::from(already_generated));
    if subsidy > 0 {
        validate_mine_address(mine_address)?;
    }

    let mut tx = Vec::with_capacity(256 + mine_address.len());
    tx.extend_from_slice(&1u32.to_le_bytes());
    tx.push(0x00);
    tx.extend_from_slice(&0u64.to_le_bytes());

    encode_compact_size(1, &mut tx);
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&u32::MAX.to_le_bytes());
    encode_compact_size(0, &mut tx);
    tx.extend_from_slice(&u32::MAX.to_le_bytes());

    let output_count = if subsidy > 0 { 2 } else { 1 };
    encode_compact_size(output_count, &mut tx);
    if subsidy > 0 {
        tx.extend_from_slice(&subsidy.to_le_bytes());
        tx.extend_from_slice(&COV_TYPE_P2PK.to_le_bytes());
        encode_compact_size(mine_address.len() as u64, &mut tx);
        tx.extend_from_slice(mine_address);
    }

    tx.extend_from_slice(&0u64.to_le_bytes());
    tx.extend_from_slice(&COV_TYPE_ANCHOR.to_le_bytes());
    encode_compact_size(32, &mut tx);
    tx.extend_from_slice(&witness_commitment);

    tx.extend_from_slice(&(height as u32).to_le_bytes());
    encode_compact_size(0, &mut tx);
    encode_compact_size(0, &mut tx);
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::{
        build_coinbase_tx, default_mine_address, parse_mine_address, validate_mine_address,
    };
    use rubin_consensus::{
        block_subsidy, constants::COV_TYPE_ANCHOR, constants::COV_TYPE_P2PK, parse_tx,
    };

    fn test_mine_address(byte: u8) -> Vec<u8> {
        let mut out = default_mine_address();
        out[1..].fill(byte);
        out
    }

    #[test]
    fn build_coinbase_tx_anchor_only_canonical_at_height_zero() {
        let mut commitment = [0u8; 32];
        for (idx, byte) in commitment.iter_mut().enumerate() {
            *byte = (idx + 1) as u8;
        }

        let tx_bytes =
            build_coinbase_tx(0, 0, &[], commitment).expect("build anchor-only coinbase");
        let (tx, _, _, consumed) = parse_tx(&tx_bytes).expect("parse coinbase");
        assert_eq!(consumed, tx_bytes.len());
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 0);
        assert_eq!(tx.outputs[0].covenant_type, COV_TYPE_ANCHOR);
        assert_eq!(tx.outputs[0].covenant_data, commitment);
        assert_eq!(tx.locktime, 0);
    }

    #[test]
    fn build_coinbase_tx_rejects_height_overflow() {
        let err = build_coinbase_tx(u64::from(u32::MAX) + 1, 0, &[], [0u8; 32]).unwrap_err();
        assert_eq!(err, "block height exceeds coinbase locktime range");
    }

    #[test]
    fn build_coinbase_tx_height_one_pays_subsidy_to_mine_address() {
        let mine_address = test_mine_address(0x42);
        let tx_bytes =
            build_coinbase_tx(1, 0, &mine_address, [0x11; 32]).expect("build subsidy coinbase");
        let (tx, _, _, consumed) = parse_tx(&tx_bytes).expect("parse coinbase");
        assert_eq!(consumed, tx_bytes.len());
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[0].value, block_subsidy(1, 0));
        assert_eq!(tx.outputs[0].covenant_type, COV_TYPE_P2PK);
        assert_eq!(tx.outputs[0].covenant_data, mine_address);
        assert_eq!(tx.outputs[1].covenant_type, COV_TYPE_ANCHOR);
    }

    #[test]
    fn build_coinbase_tx_rejects_missing_mine_address_for_subsidy_height() {
        let err = build_coinbase_tx(1, 0, &[], [0u8; 32]).unwrap_err();
        assert_eq!(err, "mine_address: expected 33 bytes, got 0");
    }

    #[test]
    fn parse_mine_address_promotes_key_id_to_canonical_covenant_data() {
        let key_id = "11".repeat(32);
        let parsed = parse_mine_address(&key_id).expect("parse").expect("some");
        validate_mine_address(&parsed).expect("validate");
        assert_eq!(parsed.len(), 33);
        assert_eq!(parsed[0], 0x01);
        assert!(parsed[1..].iter().all(|byte| *byte == 0x11));
    }
}
