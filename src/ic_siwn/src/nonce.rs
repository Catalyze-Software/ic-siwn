pub(crate) fn generate_nonce() -> String {
    use crate::RNG;
    use rand_chacha::rand_core::RngCore;

    let mut buf = [0u8; 32];
    RNG.with_borrow_mut(|rng| rng.as_mut().unwrap().fill_bytes(&mut buf));

    crate::base64::encode(buf)
}
