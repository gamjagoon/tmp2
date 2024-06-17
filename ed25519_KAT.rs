extern crate ed25519_dalek;
extern crate rand;

use ed25519_dalek::{Keypair, Signature, Signer, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

const SEED_LENGTH: usize = 32;

fn print_byte_array(bytes: &[u8]) {
    println!();
    print!("[\n        ");
    for (i, byte) in bytes.iter().enumerate() {
        if i != 0 && i % 16 == 0 {
            print!("\n        ");
        }
        print!("{:#04x}, ", byte);
    }
    println!("\n];");
}

#[test]
fn ed25519_key_generation_known_answer_test() {
    // Known answer seed (example value, replace with actual known value)
    let seed_bytes: [u8; SEED_LENGTH] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    // Generate the keypair from the seed
    let secret_key = ed25519_dalek::SecretKey::from_bytes(&seed_bytes).unwrap();
    let public_key = ed25519_dalek::PublicKey::from(&secret_key);
    let keypair = Keypair {
        secret: secret_key,
        public: public_key,
    };

    // The expected public key bytes derived from the known seed
    let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    print_byte_array(&public_key_bytes);

    // Verify that the generated public key matches the known value
    assert_eq!(
        keypair.public.to_bytes(),
        public_key_bytes,
        "Public key does not match the expected value"
    );
}

#[test]
fn ed25519_signing_known_answer_test() {
    // Known answer seed (example value, replace with actual known value)
    let seed_bytes: [u8; SEED_LENGTH] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    // Generate the keypair from the seed
    let secret_key = ed25519_dalek::SecretKey::from_bytes(&seed_bytes).unwrap();
    let public_key = ed25519_dalek::PublicKey::from(&secret_key);
    let keypair = Keypair {
        secret: secret_key,
        public: public_key,
    };

    let message: &[u8] = b"Hello, world!";

    // Generate the signature
    let signature: Signature = keypair.sign(message);

    // The expected signature bytes derived from the known seed and message
    let expected_signature_bytes: [u8; SIGNATURE_LENGTH] = [
        0xf8, 0x7b, 0x1b, 0x20, 0x0b, 0x3e, 0x7e, 0x97, 0x97, 0xe1, 0x8b, 0x54, 0xce, 0x87, 0x6b,
        0x12, 0xf8, 0x33, 0xc5, 0xe4, 0x97, 0x89, 0x0c, 0x14, 0x2b, 0x75, 0xcb, 0xf5, 0x47, 0xd6,
        0x88, 0x63, 0x8b, 0xda, 0xd5, 0x5a, 0xa0, 0xae, 0xbb, 0xce, 0xce, 0x32, 0xd0, 0x05, 0x38,
        0x5a, 0x16, 0x12, 0x80, 0xfa, 0xfa, 0x51, 0xcc, 0x14, 0xc9, 0x66, 0xb6, 0x54, 0x71, 0xab,
        0x6a, 0x89, 0xea, 0x00,
    ];
    print_byte_array(&expected_signature_bytes);

    // Verify the signature
    assert_eq!(
        signature.to_bytes(),
        expected_signature_bytes,
        "Signature does not match the expected value"
    );
}
