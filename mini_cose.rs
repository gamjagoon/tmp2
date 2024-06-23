use minicbor::Encoder;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use minicbor::bytes::{ByteArray, ByteSlice};
use std::convert::TryFrom;
use hex;

const DICE_HASH_SIZE: usize = 64;
const DICE_HIDDEN_SIZE: usize = 64;
const DICE_INLINE_CONFIG_SIZE: usize = 64;
const DICE_PRIVATE_KEY_SEED_SIZE: usize = 32;
const DICE_ID_SIZE: usize = 20;
const DICE_MAX_PUBLIC_KEY_SIZE: usize = 32 + 32; // DICE_PUBLIC_KEY_SIZE + 32
const DICE_MAX_PROTECTED_ATTRIBUTES_SIZE: usize = 16;
const DICE_COSE_KEY_ALG_VALUE: i64 = -8;
const DICE_PUBLIC_KEY_SIZE: usize = 32;
const DICE_PRIVATE_KEY_SIZE: usize = 64;
const DICE_SIGNATURE_SIZE: usize = 64;
const DICE_PROFILE_NAME: Option<&str> = None;

#[derive(Clone)]
enum DiceMode {
    NotInitialized,
    Normal,
    Debug,
    Maintenance,
}

#[derive(Clone)]
enum DiceConfigType {
    Inline,
    Descriptor,
}

struct DiceInputValues {
    code_hash: [u8; DICE_HASH_SIZE],
    code_descriptor: Option<&'static [u8]>,
    config_type: DiceConfigType,
    config_value: [u8; DICE_INLINE_CONFIG_SIZE],
    config_descriptor: Option<&'static [u8]>,
    authority_hash: [u8; DICE_HASH_SIZE],
    authority_descriptor: Option<&'static [u8]>,
    mode: DiceMode,
    hidden: [u8; DICE_HIDDEN_SIZE],
}

#[derive(Debug)]
enum DiceResult {
    Ok,
    InvalidInput,
    BufferTooSmall,
    PlatformError,
}

fn encode_cwt(
    input_values: &DiceInputValues,
    authority_id_hex: &str,
    subject_id_hex: &str,
    encoded_public_key: &[u8],
    buffer: &mut [u8],
) -> Result<usize, DiceResult> {
    const CWT_ISSUER_LABEL: i64 = 1;
    const CWT_SUBJECT_LABEL: i64 = 2;
    const CODE_HASH_LABEL: i64 = -4670545;
    const CODE_DESCRIPTOR_LABEL: i64 = -4670546;
    const CONFIG_HASH_LABEL: i64 = -4670547;
    const CONFIG_DESCRIPTOR_LABEL: i64 = -4670548;
    const AUTHORITY_HASH_LABEL: i64 = -4670549;
    const AUTHORITY_DESCRIPTOR_LABEL: i64 = -4670550;
    const MODE_LABEL: i64 = -4670551;
    const SUBJECT_PUBLIC_KEY_LABEL: i64 = -4670552;
    const KEY_USAGE_LABEL: i64 = -4670553;
    const PROFILE_NAME_LABEL: i64 = -4670554;
    const KEY_USAGE_CERT_SIGN: u8 = 32;

    let mut enc = Encoder::new(buffer);

    enc.map(7)
        .unwrap()
        .i64(CWT_ISSUER_LABEL).unwrap()
        .str(authority_id_hex).unwrap()
        .i64(CWT_SUBJECT_LABEL).unwrap()
        .str(subject_id_hex).unwrap()
        .i64(CODE_HASH_LABEL).unwrap()
        .bytes(&input_values.code_hash).unwrap();

    if let Some(code_descriptor) = input_values.code_descriptor {
        enc.i64(CODE_DESCRIPTOR_LABEL).unwrap()
            .bytes(code_descriptor).unwrap();
    }

    match input_values.config_type {
        DiceConfigType::Descriptor => {
            if let Some(config_descriptor) = input_values.config_descriptor {
                // Assuming you have a function DiceHash that computes the hash of the config_descriptor
                let config_descriptor_hash = [0u8; DICE_HASH_SIZE]; // Replace with actual hash computation
                enc.i64(CONFIG_DESCRIPTOR_LABEL).unwrap()
                    .bytes(config_descriptor).unwrap()
                    .i64(CONFIG_HASH_LABEL).unwrap()
                    .bytes(&config_descriptor_hash).unwrap();
            }
        }
        DiceConfigType::Inline => {
            enc.i64(CONFIG_DESCRIPTOR_LABEL).unwrap()
                .bytes(&input_values.config_value).unwrap();
        }
    }

    enc.i64(AUTHORITY_HASH_LABEL).unwrap()
        .bytes(&input_values.authority_hash).unwrap();

    if let Some(authority_descriptor) = input_values.authority_descriptor {
        enc.i64(AUTHORITY_DESCRIPTOR_LABEL).unwrap()
            .bytes(authority_descriptor).unwrap();
    }

    enc.i64(MODE_LABEL).unwrap()
        .bytes(&[input_values.mode.clone() as u8]).unwrap()
        .i64(SUBJECT_PUBLIC_KEY_LABEL).unwrap()
        .bytes(encoded_public_key).unwrap()
        .i64(KEY_USAGE_LABEL).unwrap()
        .bytes(&[KEY_USAGE_CERT_SIGN]).unwrap();

    if let Some(profile_name) = DICE_PROFILE_NAME {
        enc.i64(PROFILE_NAME_LABEL).unwrap()
            .str(profile_name).unwrap();
    }

    Ok(enc.into_writer().len())
}

fn sign(data: &[u8], private_key: &[u8]) -> [u8; DICE_SIGNATURE_SIZE] {
    let array: &[u8; 32] = private_key.try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(array);

    let signature = signing_key.sign(data);

    assert!(signing_key.verify(data, &signature).is_ok());

    signature.to_bytes()
}

fn encode_cose_sign1(
    protected_attributes: &[u8],
    payload: &[u8],
    signature: &[u8; DICE_SIGNATURE_SIZE],
    buffer: &mut [u8],
) -> Result<usize, DiceResult> {
    let mut enc = Encoder::new(buffer);

    enc.array(4).unwrap()
        .bytes(protected_attributes).unwrap()
        .map(0).unwrap()
        .bytes(payload).unwrap()
        .bytes(signature).unwrap();

    Ok(enc.into_writer().len())
}

fn dice_generate_certificate(
    subject_private_key_seed: &[u8; DICE_PRIVATE_KEY_SEED_SIZE],
    authority_private_key_seed: &[u8; DICE_PRIVATE_KEY_SEED_SIZE],
    input_values: &DiceInputValues,
    certificate_buffer: &mut [u8],
) -> Result<usize, DiceResult> {
    // Placeholder for actual key derivation and signing logic
    let subject_private_key = [0u8; DICE_PRIVATE_KEY_SIZE];
    let authority_private_key = [0u8; DICE_PRIVATE_KEY_SIZE];
    let subject_public_key = [0u8; DICE_PUBLIC_KEY_SIZE];
    let authority_public_key = [0u8; DICE_PUBLIC_KEY_SIZE];

    // Placeholder for actual CDI derivation logic
    let subject_id = [0u8; DICE_ID_SIZE];
    let authority_id = [0u8; DICE_ID_SIZE];

    let subject_id_hex = hex::encode(subject_id);
    let authority_id_hex = hex::encode(authority_id);

    // Placeholder for actual public key encoding logic
    let encoded_public_key = [0u8; DICE_MAX_PUBLIC_KEY_SIZE];
    let protected_attributes = [0u8; DICE_MAX_PROTECTED_ATTRIBUTES_SIZE];

    let mut cwt_buffer = vec![0u8; 1024]; // Adjust size as needed
    let cwt_size = encode_cwt(
        input_values,
        &authority_id_hex,
        &subject_id_hex,
        &encoded_public_key,
        &mut cwt_buffer,
    )?;

    // Find out how big the TBS will be
    let (payload_start, tbs_size) = encode_cose_tbs(
        &protected_attributes,
        cwt_size,
        None,
        certificate_buffer,
    )?;

    // Now we can encode the payload directly into the allocated BSTR in the TBS
    let final_cwt_size = encode_cwt(
        input_values,
        &authority_id_hex,
        &subject_id_hex,
        &encoded_public_key,
        &mut certificate_buffer[payload_start..],
    )?;

    if final_cwt_size != cwt_size {
        return Err(DiceResult::PlatformError);
    }

    // Sign the now-complete TBS
    let signature = sign(&certificate_buffer[..tbs_size], &authority_private_key);

    // Produce the complete COSE_Sign1, including the signature
    let certificate_size = encode_cose_sign1(
        &protected_attributes,
        &certificate_buffer[payload_start..payload_start + final_cwt_size],
        &signature,
        certificate_buffer,
    )?;

    Ok(certificate_size)
}

fn main() {
    // Example usage of dice_generate_certificate
    let subject_private_key_seed = [0u8; DICE_PRIVATE_KEY_SEED_SIZE];
    let authority_private_key_seed = [0u8; DICE_PRIVATE_KEY_SEED_SIZE];
    let input_values = DiceInputValues {
        code_hash: [0u8; DICE_HASH_SIZE],
        code_descriptor: None,
        config_type: DiceConfigType::Inline,
        config_value: [0u8; DICE_INLINE_CONFIG_SIZE],
        config_descriptor: None,
        authority_hash: [0u8; DICE_HASH_SIZE],
        authority_descriptor: None,
        mode: DiceMode::Normal,
        hidden: [0u8; DICE_HIDDEN_SIZE],
    };

    let mut certificate_buffer = vec![0u8; 2048]; // Adjust size as needed
    match dice_generate_certificate(
        &subject_private_key_seed,
        &authority_private_key_seed,
        &input_values,
        &mut certificate_buffer,
    ) {
        Ok(certificate_size) => {
            println!("Certificate generated, size: {}", certificate_size);
        }
        Err(result) => {
            println!("Failed to generate certificate: {:?}", result);
        }
    }
}
