use sha2::{Digest, Sha512};
use std::vec::Vec;

const BLOCK_SIZE: usize = 128;

pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
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
