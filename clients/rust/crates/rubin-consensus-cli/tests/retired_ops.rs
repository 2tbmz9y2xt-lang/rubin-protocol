use std::io::Write;
use std::process::{Command, Stdio};

fn run_cli(payload: &str) -> serde_json::Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rubin-consensus-cli"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn rubin-consensus-cli");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write request");

    let output = child.wait_with_output().expect("wait for cli");
    assert!(
        output.status.success(),
        "cli exited with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("json response")
}

#[test]
fn retired_core_ext_tooling_ops_return_unknown_op() {
    for op in [
        "txctx_spend_vector",
        "txctx_governance_vector",
        "ext_envelope_parse",
        "ext_activation_check",
        "ext_pre_activation_spend",
        "ext_enforcement_check",
        "ext_error_priority",
        "ext_duplicate_profile",
    ] {
        let response = run_cli(&format!(r#"{{"op":"{op}"}}"#));

        assert_eq!(
            response.get("ok").and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            response.get("err").and_then(serde_json::Value::as_str),
            Some("unknown op")
        );
    }
}
