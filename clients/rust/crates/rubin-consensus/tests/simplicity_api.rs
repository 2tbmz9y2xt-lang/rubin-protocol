use rubin_consensus::simplicity::*;
#[test] #[rustfmt::skip]
fn public_simplicity_api_exposes_decode_and_jet_metadata() { let got: Program = decode(&[0x60], &[], DecodeOptions { semantics_version: SEMANTICS_VERSION, covenant_program_cmr: None }).unwrap(); let jet: Jet = got.jet.unwrap(); assert_eq!((got.needs_witness, jet.id, jet.sub_op, jet.name, jet.cmr), (false, 0x0001, 0x00, "sha3_256", got.cmr)); assert_eq!(lookup_jet(0x0001, 0x00).unwrap(), jet); }
