use sha2::{Digest, Sha512};
use std::vec::Vec;
use ed25519_dalek::Signer;
use hex_literal::hex;

const BLOCK_SIZE: usize = 128;
const ASYM_SALT : [u8; 64] = hex!("63B6A04D2C077FC10F639F21DA793844356CC2B0B441B3A77124035C03F8E1BE6035D31F282821A7450A02222AB1B3CFF1679B05AB1CA5D1AFFB789CCD2B0B3B");
const ID_SALT : [u8; 64] = hex!("DBDBAEBC8020DA9FF0DD5A24C83AA5A54286DFC263031E329B4DA148430659FE62CDB5B7E1E00FC680306711EB444AF77209359496FCFF1DB9520BA51C7B29EA");

pub fn ed25519_sign(data: &[u8], private_key: &[u8]) -> [u8; 64] {
    let array: &[u8; 32] = private_key.try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(array);

    let signature = signing_key.sign(data);

    assert!(signing_key.verify(data, &signature).is_ok());

    signature.to_bytes()
}

pub fn asyn_kdf(input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let private_key:[u8; 32]  = hkdf(ASYM_SALT.as_slice(), input, "Key Pair".as_bytes(), 32).as_slice().try_into().unwrap();
    let public_key = ed25519_dalek::SigningKey::from_bytes(&private_key).verifying_key().to_owned().to_bytes();
    (private_key, public_key)
}

pub fn gen_id(input: &[u8]) -> [u8; 20] {
    hkdf(ID_SALT.as_slice(), input, "ID".as_bytes(), 32).as_slice().try_into().unwrap()
}

pub fn generate_next_layer_cdi(prev_cdi_attest: &[u8; 32], prev_cdi_seal:&[u8; 32], code: &[u8; 64],config: &[u8; 64],authority: &[u8; 64],mode: &[u8; 1],hidden: &[u8; 64]) -> ([u8; 32], [u8; 32]) {

    let next_cdi_attest: [u8; 32] = gen_cdi_attest(prev_cdi_attest, code, config, authority, mode, hidden);
    let next_cdi_seal: [u8; 32] = gen_cdi_seal(prev_cdi_seal, authority, mode, hidden);
    (next_cdi_attest,next_cdi_seal)
}

fn gen_cdi_attest(input: &[u8;32], code: &[u8; 64],config: &[u8; 64],authority: &[u8; 64],mode: &[u8; 1],hidden: &[u8; 64]) -> [u8; 32] {
    let mut merged = Vec::new();
    merged.extend_from_slice(code);
    merged.extend_from_slice(config);
    merged.extend_from_slice(authority);
    merged.extend_from_slice(mode);
    merged.extend_from_slice(hidden);
    let inputs: [u8; 64*4 + 1] = merged.as_slice().try_into().unwrap();
    let hash: [u8; 64] = Sha512::digest(inputs).into();
    hkdf(hash.as_slice(), input, "CDI_Attest".as_bytes(), 32).as_slice().try_into().unwrap()
}

fn gen_cdi_seal(input: &[u8;32], authority: &[u8; 64],mode: &[u8; 1],hidden: &[u8; 64]) -> [u8; 32] {
    let mut merged = Vec::new();
    merged.extend_from_slice(authority);
    merged.extend_from_slice(mode);
    merged.extend_from_slice(hidden);
    let inputs: [u8; 64*2 + 1] = merged.as_slice().try_into().unwrap();
    let hash: [u8; 64] = Sha512::digest(inputs).into();
    hkdf(hash.as_slice(), input, "CDI_Seal".as_bytes(), 32).as_slice().try_into().unwrap()
}

fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    // HKDF Extract
    let prk = hkdf_extract(salt, ikm);

    // HKDF Expand
    hkdf_expand(&prk, info, length)
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut ipad = vec![0x36; BLOCK_SIZE];
    let mut opad = vec![0x5c; BLOCK_SIZE];

    let mut key = key.to_vec();
    if key.len() > BLOCK_SIZE {
        key = Sha512::digest(&key).to_vec();
    }
    key.resize(BLOCK_SIZE, 0);

    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    let mut hasher = Sha512::new();
    hasher.update(&ipad);
    hasher.update(data);
    let inner_hash = hasher.finalize();

    let mut hasher = Sha512::new();
    hasher.update(&opad);
    hasher.update(inner_hash);
    hasher.finalize().to_vec()
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    hmac_sha512(salt, ikm)
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut okm = Vec::new();
    let mut previous_block = vec![];

    for i in 0..((length + 63) / 64) {
        let mut data = previous_block.clone();
        data.extend_from_slice(info);
        data.push((i + 1) as u8);
        previous_block = hmac_sha512(prk, &data);
        okm.extend_from_slice(&previous_block);
    }

    okm.truncate(length);
    okm
}



#[cfg(test)]
mod tests {
    use super::*;
    use hkdf::Hkdf;
    use sha2::Sha512;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn kat_cdi_test() {
        let cdi0_attest = [0_u8; 32];
        let cdi0_seal = [0_u8; 32];
        let code = [0_u8; 64];
        let config = [0_u8; 64];
        let authority = [0_u8; 64];
        let mode = [0_u8; 1];
        let hidden = [0_u8; 64];
        let expect_cdi1_attest: [u8; 32] = [
            0xFB, 0xFC, 0x67, 0x97, 0x71, 0x34, 0x2E, 0xEA, 0xCB, 0x90, 0x86, 0x59, 0xCE, 0x49, 0xD6, 0xB6,
            0x3B, 0x45, 0x35, 0xDA, 0x2C, 0x51, 0x43, 0x3D, 0x7F, 0x04, 0xEF, 0xA6, 0x31, 0x9E, 0x0C, 0x19,
        ];
        let expect_cdi1_seal: [u8; 32] = [
            0x8F, 0xF8, 0xB2, 0x25, 0x71, 0x32, 0x5E, 0x7D, 0xEF, 0xEF, 0xBF, 0xEA, 0x8D, 0xF1, 0xC9, 0xF3,
            0x4B, 0xF4, 0xD9, 0xEE, 0x03, 0xB7, 0x5B, 0x78, 0x82, 0x19, 0xC6, 0xB1, 0xEF, 0x49, 0xBD, 0xC5,
        ];

        let result = generate_next_layer_cdi(&cdi0_attest, &cdi0_seal, &code, &config, &authority, &mode, &hidden);
        assert_eq!(result.0, expect_cdi1_attest, "CDI Attest does not match expected value");
        assert_eq!(result.1, expect_cdi1_seal, "CDI Seal does not match expected value");
    }

    #[test]
    fn hkdf_sha512_known_answer_test() {
        // Test vectors
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
        let prk_expected = [
            250, 218, 39, 156, 195, 119, 246, 93, 238, 77, 100, 218, 70, 147, 126, 218, 103, 156,
            107, 73, 1, 134, 61, 73, 77, 227, 118, 54, 213, 23, 234, 233, 36, 46, 118, 45, 216, 6,
            143, 191, 192, 245, 42, 152, 229, 185, 157, 8, 11, 23, 106, 47, 77, 84, 200, 128, 113,
            175, 75, 165, 141, 71, 244, 65,
        ];
        let okm_expected = [
            163, 19, 43, 185, 165, 254, 145, 152, 10, 209, 19, 191, 50, 160, 250, 178, 92, 60, 223,
            85, 237, 37, 52, 30, 172, 244, 85, 181, 52, 243, 126, 128, 60, 59, 232, 41, 246, 197,
            9, 228, 155, 249, 222, 5, 6, 33, 117, 249, 225, 11, 216, 228, 42, 98, 87, 157, 227, 20,
            210, 30, 57, 10, 232, 242, 172, 67, 230, 233, 67, 90, 115, 153, 120, 233, 249, 226,
            251, 248, 214, 216, 195, 53, 99, 6, 129, 224, 2, 26, 251, 174, 147, 116, 221, 158, 142,
            27,
        ];

        // HKDF Extract
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(prk, prk_expected, "PRK does not match the expected value");

        // HKDF Expand
        let okm = hkdf_expand(&prk, &info, okm_expected.len());
        assert_eq!(okm, okm_expected, "OKM does not match the expected value");

        let okm2 = hkdf(&salt, &ikm, &info, okm_expected.len());

        assert_eq!(
            okm, okm2,
            "HKDF-Expand using hkdf crate does not match the expected value"
        );

        // Validate using hkdf crate
        let hk = Hkdf::<Sha512>::new(Some(&salt), &ikm);
        let mut okm = vec![0u8; okm_expected.len()];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(
            okm2, okm_expected,
            "HKDF-Expand using hkdf crate does not match the expected value"
        );
    }
}

fn main() {

}
