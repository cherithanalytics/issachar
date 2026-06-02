/// Probes whether ML-DSA-87 and SPHINCS+-SHAKE256-256f-simple sign deterministically,
/// then emits test vectors accordingly.
///
/// For each algorithm: generate a keypair, sign a fixed message twice, compare.
/// If signing is deterministic the signature is stable and we emit (pk, sk, sig).
/// If randomized we emit (pk, sk) for a keypair test and (pk, sig) for a
/// verification-only test captured from one run.
use oqs::sig::{Algorithm, Sig};

const MESSAGE: &[u8] = b"pqc test vector message";

fn probe_and_emit(label: &str, alg: Algorithm) {
    oqs::init();
    let scheme = Sig::new(alg).unwrap();
    let (pk, sk) = scheme.keypair().unwrap();

    let sig1 = scheme.sign(MESSAGE, &sk).unwrap();
    let sig2 = scheme.sign(MESSAGE, &sk).unwrap();
    let deterministic = sig1.as_ref() == sig2.as_ref();

    scheme.verify(MESSAGE, &sig1, &pk).unwrap();

    println!("{label}_DETERMINISTIC={deterministic}");
    println!("{label}_PK={}", hex::encode(pk.as_ref()));
    println!("{label}_SK={}", hex::encode(sk.as_ref()));
    println!("{label}_SIG={}", hex::encode(sig1.as_ref()));
}

fn main() {
    probe_and_emit("ML_DSA_87", Algorithm::MlDsa87);
    probe_and_emit("SPHINCS_SHAKE256_256F", Algorithm::SphincsShake256fSimple);
}
