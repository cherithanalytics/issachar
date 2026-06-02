use std::fs;

use issachar::strobe::FLAG_A;
use issachar::strobe::FLAG_C;
use issachar::strobe::FLAG_I;
use issachar::strobe::FLAG_M;
use issachar::strobe::FLAG_T;
use issachar::strobe::Strobe;
use serde::Deserialize;

// ── JSON schema (mirrors StrobeGo's Operation / TestVector types) ──────────

#[derive(Debug, Deserialize)]
struct TestVectors {
    test_vectors: Vec<TestVector>,
}

#[derive(Debug, Deserialize)]
struct TestVector {
    name: String,
    operations: Vec<Operation>,
}

#[derive(Debug, Deserialize)]
struct Operation {
    name: String,
    // init only
    custom_string: Option<String>,
    security: Option<u32>,
    // all others
    #[serde(default)]
    meta: bool,
    input_data: Option<String>, // hex-encoded
    #[serde(default)]
    input_length: usize,
    output: Option<String>, // hex-encoded expected output
    state_after: String,    // hex-encoded expected full state
    #[serde(default)]
    stream: bool, // more=true continuation
}

// ── Flag lookup ────────────────────────────────────────────────────────────

fn flags_for(name: &str) -> u8 {
    match name {
        "AD" => FLAG_A,
        "KEY" => FLAG_A | FLAG_C,
        "PRF" => FLAG_I | FLAG_A | FLAG_C,
        "RATCHET" => FLAG_C,
        "send_CLR" => FLAG_A | FLAG_T,
        "recv_CLR" => FLAG_I | FLAG_A | FLAG_T,
        "send_ENC" => FLAG_A | FLAG_C | FLAG_T,
        "recv_ENC" => FLAG_I | FLAG_A | FLAG_C | FLAG_T,
        "send_MAC" => FLAG_C | FLAG_T,
        "recv_MAC" => FLAG_I | FLAG_C | FLAG_T,
        other => unreachable!("unknown operation: {other}"),
    }
}

// ── StrobeGo output semantics ──────────────────────────────────────────────
//
// StrobeGo's Operate returns:
//   - The (possibly transformed) data for: PRF, recv_ENC, recv_CLR, send_ENC, send_CLR, send_MAC
//   - A single-byte OR-fold of output bytes for recv_MAC (0x00=valid, else invalid)
//   - nil / nothing for: AD, KEY, RATCHET

fn expected_output(flags: u8, raw: &[u8]) -> Option<Vec<u8>> {
    // Returns data to application: I|A both set
    if (flags & (FLAG_I | FLAG_A)) == (FLAG_I | FLAG_A) {
        return Some(raw.to_vec());
    }
    // Returns data to transport: T set, I clear
    if (flags & (FLAG_I | FLAG_T)) == FLAG_T {
        return Some(raw.to_vec());
    }
    // recv_MAC: I|T set, A clear → collapse to single failure byte
    if (flags & (FLAG_I | FLAG_A | FLAG_T)) == (FLAG_I | FLAG_T) {
        let failure = raw.iter().fold(0u8, |acc, &b| acc | b);
        return Some(vec![failure]);
    }
    None
}

// ── Vector runner ──────────────────────────────────────────────────────────

#[test]
fn test_strobe_go_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/strobe_test_vectors.json");
    let json = fs::read_to_string(path).expect("tests/strobe_test_vectors.json not found");
    let tvs: TestVectors = serde_json::from_str(&json).unwrap();

    for tv in &tvs.test_vectors {
        let mut strobe: Option<Strobe> = None;

        for op in &tv.operations {
            match op.name.as_str() {
                "init" => {
                    if op.security.unwrap_or(256) != 256 {
                        break; // skip non-256-bit vectors
                    }
                    let proto = op.custom_string.as_deref().unwrap_or("");
                    let s = Strobe::new(proto.as_bytes());
                    assert_eq!(
                        hex::encode(s.as_bytes()),
                        op.state_after,
                        "[{}] init state mismatch",
                        tv.name,
                    );
                    strobe = Some(s);
                }

                op_name => {
                    let s = strobe
                        .as_mut()
                        .unwrap_or_else(|| panic!("[{}] op {op_name} before init", tv.name));

                    let mut flags = flags_for(op_name);
                    if op.meta {
                        flags |= FLAG_M;
                    }

                    // Build input: hex-decoded data OR zero bytes of input_length
                    let mut input: Vec<u8> = match &op.input_data {
                        Some(h) if !h.is_empty() => hex::decode(h).unwrap_or_else(|e| {
                            panic!("[{}] {op_name} bad input_data hex: {e}", tv.name)
                        }),
                        _ => vec![0u8; op.input_length],
                    };

                    s.operate(op.meta, flags_for(op_name), &mut input, op.stream);

                    // Verify output when the vector provides one
                    if let Some(expected) = &op.output {
                        let actual = expected_output(flags, &input).unwrap_or_else(|| {
                            panic!(
                                "[{}] {op_name} produced no output but vector expects {expected}",
                                tv.name
                            )
                        });
                        assert_eq!(
                            hex::encode(&actual),
                            *expected,
                            "[{}] {op_name} output mismatch",
                            tv.name,
                        );
                    }

                    // Always verify state
                    assert_eq!(
                        hex::encode(s.as_bytes()),
                        op.state_after,
                        "[{}] {op_name} state mismatch",
                        tv.name,
                    );
                }
            }
        }
    }
}
