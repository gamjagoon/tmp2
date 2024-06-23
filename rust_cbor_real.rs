mod dice;
use minicbor::{CborLen, Encoder};
use hex;

const DICE_HASH_SIZE: usize = 64;
const DICE_HIDDEN_SIZE: usize = 64;
const DICE_INLINE_CONFIG_SIZE: usize = 64;
const DICE_PRIVATE_KEY_SEED_SIZE: usize = 32;
const DICE_CDI_SIZE: usize = 32;
const DICE_ID_SIZE: usize = 20;
const DICE_MAX_PUBLIC_KEY_SIZE: usize = 32 + 32; // DICE_PUBLIC_KEY_SIZE + 32
const DICE_MAX_PROTECTED_ATTRIBUTES_SIZE: usize = 16;
const DICE_COSE_KEY_ALG_VALUE: i64 = -8;
const DICE_PUBLIC_KEY_SIZE: usize = 32;
const DICE_PRIVATE_KEY_SIZE: usize = 64;
const DICE_SIGNATURE_SIZE: usize = 64;
const DICE_PROFILE_NAME: Option<&str> = None;

const K_COSE_KEY_KTY_LABEL: i64 = 1;
const K_COSE_KEY_TYPE_OKP: i64 = 1;
const K_COSE_KEY_ALG_LABEL: i64 = 3;
const K_COSE_ALG_ED_DSA: i64 = DICE_COSE_KEY_ALG_VALUE;
const K_COSE_KEY_OPS_LABEL: i64 = 4;
const K_COSE_KEY_OPS_VERIFY: i64 = 2;
const K_COSE_OKP_CRV_LABEL: i64 = -1;
const K_COSE_CRV_ED25519: i64 = 6;
const K_COSE_OKP_XLABEL: i64 = -2;

#[derive(Clone)]
enum DiceMode {
    NotInitialized = 0x0,
    Normal,
    Debug,
    Maintenance,
}

#[derive(Clone)]
enum DiceConfigType {
    Inline = 0x0,
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

fn cose_encode_public_key(buffer: &mut [u8], public_key: &[u8; DICE_PUBLIC_KEY_SIZE]) -> Result<usize, DiceResult> {
    let mut enc = Encoder::new(buffer);

    enc.map(1).unwrap();

    // Add the key type
    enc.i64(K_COSE_KEY_KTY_LABEL).unwrap();
    enc.i64(K_COSE_KEY_TYPE_OKP).unwrap();

    // Add the algorithm
    enc.i64(K_COSE_KEY_ALG_LABEL).unwrap();
    enc.i64(K_COSE_ALG_ED_DSA).unwrap();

    // Add the KeyOps
    enc.i64(K_COSE_KEY_OPS_LABEL).unwrap();
    enc.array(1).unwrap();
    enc.i64(K_COSE_KEY_OPS_VERIFY).unwrap();

    // Add the curve
    enc.i64(K_COSE_OKP_CRV_LABEL).unwrap();
    enc.i64(K_COSE_CRV_ED25519).unwrap();

    // Add the public key
    enc.i64(K_COSE_OKP_XLABEL).unwrap();
    enc.bytes(public_key).unwrap();

    Ok(enc.into_writer().len())
}

fn encode_protected_attributes(buffer: &mut [u8]) -> Result<usize, DiceResult> {
    let mut enc = Encoder::new(buffer);

    enc.map(1).unwrap();

    // Constants per RFC 8152
    let k_cose_header_alg_label = 1;

    enc.i64(k_cose_header_alg_label).unwrap();
    enc.i64(DICE_COSE_KEY_ALG_VALUE).unwrap();

    Ok(enc.into_writer().len())
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

    let mut map_pairs: u64 = 7;
    if input_values.code_descriptor.is_some_and(|x| x.len() > 0) {
        map_pairs += 1;
    }
    match input_values.config_type {
        DiceConfigType::Descriptor =>map_pairs += 2,
        DiceConfigType::Inline =>map_pairs += 1,
    }
    if input_values.authority_descriptor.is_some_and(|x| x.len() > 0) {
        map_pairs += 1;
    }
    if DICE_PROFILE_NAME.is_some() {
        map_pairs += 1;
    }

    enc.map(map_pairs).unwrap()
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

fn encode_cose_tbs(
    protected_attributes: &[u8],
    aad: Option<&[u8]>,
    buffer: &mut [u8],
    payload: &[u8],
    encoded_size: &mut usize
) -> Result<DiceResult, DiceResult> {
    let mut enc = Encoder::new(buffer);

    // TBS is an array of four elements
    enc.array(4).unwrap();
    // Context string field
    enc.str("Signature1").unwrap();
    // Protected attributes from COSE_Sign1
    enc.bytes(protected_attributes).unwrap();
    // Additional authenticated data
    if let Some(aad) = aad {
        enc.bytes(aad).unwrap();
    } else {
        enc.bytes(&[]).unwrap();
    }

    enc.bytes(payload).unwrap();

    *encoded_size = enc.into_writer().len();

    Ok(DiceResult::Ok)
}

fn dice_generate_certificate(
    next_cdi_attest: &[u8; DICE_CDI_SIZE],
    current_cdi_attest: &[u8; DICE_CDI_SIZE],
    input_values: &DiceInputValues,
    certificate_buffer: &mut [u8],
) -> Result<usize, DiceResult> {
    // Placeholder for actual key derivation and signing logic
    let (_, subject_public_key): ([u8; 32], [u8; 32]) = dice::asyn_kdf(next_cdi_attest);
    let (authority_private_key, authority_public_key): ([u8; 32], [u8; 32]) = dice::asyn_kdf(current_cdi_attest);

    // Placeholder for actual CDI derivation logic
    let subject_id = dice::gen_id(subject_public_key.as_slice());
    let authority_id = dice::gen_id(authority_public_key.as_slice());

    let subject_id_hex = hex::encode(subject_id);
    let authority_id_hex = hex::encode(authority_id);
    println!("{:X?}",subject_id_hex);
    for i in &subject_id {
        print!("{:02X}", i);
    }
    println!();
    // Placeholder for actual public key encoding logic
    let mut encoded_public_key =  [0u8; DICE_MAX_PUBLIC_KEY_SIZE];
    let mut protected_attributes = [0u8; DICE_MAX_PROTECTED_ATTRIBUTES_SIZE];

    let encode_public_key_len = DICE_MAX_PUBLIC_KEY_SIZE - cose_encode_public_key(&mut encoded_public_key, &subject_public_key).unwrap();

    let attributes_len = DICE_MAX_PROTECTED_ATTRIBUTES_SIZE - encode_protected_attributes(&mut protected_attributes).unwrap();

    // Find out how big the TBS will be
    let mut payload:Vec<u8> = vec![0; 512];
    let mut encoded_size = 0;
    // Now we can encode the payload directly into the allocated BSTR in the TBS
    let cwt_size = payload.len() - encode_cwt(
        input_values,
        &authority_id_hex,
        &subject_id_hex,
        &encoded_public_key[..encode_public_key_len],
        payload.as_mut(),
    )?;

    encode_cose_tbs(
        &protected_attributes[..attributes_len],
        None,
        certificate_buffer,
        &payload,
        &mut encoded_size
    )?;

    encoded_size = certificate_buffer.len() - encoded_size;

    // Sign the now-complete TBS
    let signature = dice::ed25519_sign(&certificate_buffer[..encoded_size], &authority_private_key);

    for i in &payload[..cwt_size] {
        print!("{:02X}", i);
    }
    println!();

    for i in &certificate_buffer[..encoded_size] {
        print!("{:02X}", i);
    }
    println!();

    // Produce the complete COSE_Sign1, including the signature
    let certificate_size = {
        encode_cose_sign1(
            &protected_attributes[..attributes_len],
            &payload[..cwt_size],
            &signature,
            certificate_buffer,
        )?
    };

    Ok(certificate_buffer.len() - certificate_size)
}

fn main() {
    // Example usage of dice_generate_certificate
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
    let mut certificate_buffer = vec![0u8; 1024]; // Adjust size as needed
    let input_cdi: [u8; DICE_CDI_SIZE] = [0; DICE_CDI_SIZE];
    let input_seal: [u8; DICE_CDI_SIZE] = [0; DICE_CDI_SIZE];
    let next_cdi = dice::generate_next_layer_cdi(&input_cdi, &input_seal, &input_values.code_hash, &input_values.config_value, &input_values.authority_hash, &[0 as u8; 1], &input_values.hidden);

    let cert_len = match dice_generate_certificate(
        &next_cdi.0,
        &input_cdi,
        &input_values,
        &mut certificate_buffer,
    ) {
        Ok(certificate_size) => {
            println!("Certificate generated, size: {}", certificate_size);
            certificate_size
        }
        Err(result) => {
            println!("Failed to generate certificate: {:?}", result);
            0
        }
    };
    for i in &certificate_buffer[..cert_len] {
        print!("{:02X}", i);
    }
}

// https://cbor.nemo157.com/

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use sha2::Sha512;

    #[test]
    fn kat_cose_zero_input() {
        let expected_output: [u8; 441] = [
            0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0, 0x59, 0x01, 0x6e, 0xa8, 0x01, 0x78,
            0x28, 0x37, 0x61, 0x30, 0x36, 0x65, 0x65, 0x65, 0x34, 0x31, 0x62, 0x37,
            0x38, 0x39, 0x66, 0x34, 0x38, 0x36, 0x33, 0x64, 0x38, 0x36, 0x62, 0x38,
            0x37, 0x37, 0x38, 0x62, 0x31, 0x61, 0x32, 0x30, 0x31, 0x61, 0x36, 0x66,
            0x65, 0x64, 0x64, 0x35, 0x36, 0x02, 0x78, 0x28, 0x36, 0x37, 0x63, 0x32,
            0x32, 0x61, 0x38, 0x38, 0x35, 0x39, 0x30, 0x36, 0x32, 0x62, 0x39, 0x38,
            0x36, 0x38, 0x31, 0x38, 0x65, 0x38, 0x65, 0x37, 0x32, 0x62, 0x30, 0x62,
            0x63, 0x64, 0x39, 0x66, 0x35, 0x39, 0x33, 0x34, 0x39, 0x63, 0x38, 0x39,
            0x3a, 0x00, 0x47, 0x44, 0x50, 0x58, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a,
            0x00, 0x47, 0x44, 0x53, 0x58, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00,
            0x47, 0x44, 0x54, 0x58, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x47,
            0x44, 0x56, 0x41, 0x00, 0x3a, 0x00, 0x47, 0x44, 0x57, 0x58, 0x2d, 0xa5,
            0x01, 0x01, 0x03, 0x27, 0x04, 0x81, 0x02, 0x20, 0x06, 0x21, 0x58, 0x20,
            0x0d, 0x14, 0xe5, 0xde, 0x29, 0x2e, 0xb1, 0xc8, 0xb3, 0x1b, 0xea, 0xe4,
            0x3a, 0xb5, 0x5d, 0x8e, 0x9d, 0xc0, 0x14, 0xb7, 0x3e, 0xaa, 0x83, 0xb9,
            0x25, 0xa0, 0x78, 0x8c, 0xc6, 0x2e, 0x5c, 0x8d, 0x3a, 0x00, 0x47, 0x44,
            0x58, 0x41, 0x20, 0x58, 0x40, 0xf9, 0x9b, 0xd6, 0xdb, 0xc1, 0x24, 0x71,
            0x53, 0xc1, 0x0f, 0x88, 0x1c, 0x0f, 0x5f, 0x33, 0xbf, 0x02, 0x23, 0xd2,
            0x22, 0x32, 0x71, 0x24, 0x41, 0xb1, 0x28, 0xd3, 0x83, 0xde, 0x32, 0x1b,
            0x67, 0xc0, 0x9a, 0x1f, 0x45, 0x91, 0xc4, 0x20, 0xdc, 0xc9, 0xd6, 0x21,
            0x21, 0xec, 0xa3, 0xd3, 0x89, 0x7a, 0x24, 0x4d, 0xcb, 0xe1, 0x1a, 0x0f,
            0x9a, 0xb7, 0x9f, 0x67, 0x09, 0x3f, 0xee, 0x56, 0x0f];

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
        let mut certificate_buffer = vec![0u8; 1024]; // Adjust size as needed
        let input_cdi: [u8; DICE_CDI_SIZE] = [0; DICE_CDI_SIZE];
        let input_seal: [u8; DICE_CDI_SIZE] = [0; DICE_CDI_SIZE];
        let next_cdi = dice::generate_next_layer_cdi(&input_cdi, &input_seal, &input_values.code_hash, &input_values.config_value, &input_values.authority_hash, &[0 as u8; 1], &input_values.hidden);

        let cert_len = match dice_generate_certificate(
            &next_cdi.0,
            &input_cdi,
            &input_values,
            &mut certificate_buffer,
        ) {
            Ok(certificate_size) => {
                println!("Certificate generated, size: {}", certificate_size);
                certificate_size
            }
            Err(result) => {
                println!("Failed to generate certificate: {:?}", result);
                0
            }
        };
        for i in &certificate_buffer[..cert_len] {
            print!("{:02X}", i);
        }
        println!();
        for i in &expected_output {
            print!("{:02X}", i);
        }
        println!();
        debug_assert_eq!(cert_len, expected_output.len(), "Does not match expected len");
        debug_assert_eq!(certificate_buffer.as_slice()[..cert_len], expected_output, "Does not match expected value");

        
    }

    fn derive_fake_input_value(seed: &[u8]) -> Vec<u8> {
        let mut context = Sha512::digest(seed);
        let mut output = Vec::new();
    
        while output.len() < seed.len() {
            let mut tmp = [0u8; 64];
            tmp.copy_from_slice(&context.finalize().as_slice());
            context = Sha512::digest(&tmp);
            let to_copy = seed.len() - output.len().min(64);
            output.extend_from_slice(&tmp[..to_copy]);
        }
    
        output
    }

    fn kat_cose_hash_only_input() {
        let expected_attest: [u8; 32] = [
            0x08, 0x4e, 0xf4, 0x06, 0xc6, 0x9b, 0xa7, 0x4b, 0x1e, 0x24, 0xd0,
            0x62, 0xf9, 0xab, 0x8a, 0x8d, 0x89, 0xda, 0x6e, 0x03, 0xe4, 0xc6,
            0xb1, 0x22, 0x85, 0x7c, 0xf7, 0x4f, 0xd6, 0xa4, 0xbe, 0xe5
        ];
        let expected_seal : [u8; 32] = [
            0x90, 0xc9, 0xa2, 0x86, 0x5d, 0xf4, 0xfa, 0x58, 0x30, 0x64, 0x3d,
            0x6c, 0xae, 0xf0, 0x7c, 0x76, 0xae, 0xaa, 0x15, 0x61, 0x98, 0x28,
            0xf1, 0xbd, 0xa7, 0xf7, 0x44, 0x82, 0xe2, 0xf0, 0xae, 0x1e
        ];
        let expected_output: [u8; 441] = [
            0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0, 0x59, 0x01, 0x6e, 0xa8, 0x01, 0x78,
            0x28, 0x34, 0x37, 0x35, 0x37, 0x30, 0x38, 0x65, 0x62, 0x33, 0x62, 0x34,
            0x32, 0x36, 0x66, 0x33, 0x38, 0x36, 0x63, 0x66, 0x63, 0x65, 0x38, 0x66,
            0x33, 0x62, 0x61, 0x66, 0x35, 0x34, 0x33, 0x39, 0x30, 0x34, 0x36, 0x32,
            0x37, 0x38, 0x64, 0x66, 0x61, 0x02, 0x78, 0x28, 0x30, 0x64, 0x30, 0x34,
            0x30, 0x65, 0x32, 0x66, 0x34, 0x36, 0x30, 0x30, 0x35, 0x32, 0x61, 0x35,
            0x33, 0x31, 0x31, 0x63, 0x31, 0x62, 0x39, 0x31, 0x64, 0x62, 0x66, 0x39,
            0x62, 0x34, 0x34, 0x30, 0x38, 0x33, 0x33, 0x32, 0x65, 0x63, 0x32, 0x39,
            0x3a, 0x00, 0x47, 0x44, 0x50, 0x58, 0x40, 0xb7, 0xd4, 0x0c, 0xcb, 0x22,
            0x5b, 0xa5, 0x78, 0x8f, 0x98, 0xff, 0x9e, 0x86, 0x93, 0x75, 0xf6, 0x90,
            0xac, 0x50, 0xcf, 0x9e, 0xbd, 0x0a, 0xfe, 0xb1, 0xd9, 0xc2, 0x4e, 0x52,
            0x19, 0xe4, 0xde, 0x29, 0xe5, 0x61, 0xf3, 0xf9, 0x29, 0xe8, 0x40, 0x87,
            0x7a, 0xdd, 0x17, 0x48, 0x05, 0x89, 0x7e, 0x2b, 0xcb, 0x54, 0x79, 0xcc,
            0x66, 0xf1, 0xb3, 0x13, 0x29, 0x0c, 0x68, 0x96, 0xb2, 0xbb, 0x8f, 0x3a,
            0x00, 0x47, 0x44, 0x53, 0x58, 0x40, 0xcf, 0x99, 0x7b, 0xea, 0x2e, 0x2c,
            0x86, 0xa0, 0x7b, 0x52, 0x09, 0xc8, 0xb5, 0x3c, 0x41, 0x12, 0x29, 0x28,
            0x1a, 0x82, 0x0d, 0x49, 0x9c, 0x95, 0xcb, 0x0b, 0x1b, 0x31, 0x1a, 0x01,
            0x9c, 0xf2, 0x66, 0x1a, 0xd9, 0xb5, 0xce, 0x52, 0x59, 0xcb, 0xf4, 0x81,
            0x9b, 0x21, 0xaf, 0x32, 0x5d, 0x07, 0xa0, 0x1e, 0x91, 0x59, 0x6f, 0x06,
            0x55, 0x10, 0x8e, 0x2e, 0x08, 0x88, 0x52, 0x28, 0x86, 0x7f, 0x3a, 0x00,
            0x47, 0x44, 0x54, 0x58, 0x40, 0x22, 0x52, 0x60, 0x17, 0xef, 0x2c, 0xa1,
            0xf6, 0xcb, 0xed, 0x39, 0xd5, 0xe2, 0xaa, 0x65, 0x20, 0xfb, 0xad, 0x82,
            0x93, 0xe5, 0x78, 0x23, 0x22, 0x97, 0xc1, 0x6e, 0x6a, 0x4e, 0x36, 0xd7,
            0x6a, 0x61, 0x39, 0x08, 0x21, 0xd4, 0xfe, 0x92, 0x5f, 0x36, 0x2d, 0xeb,
            0x5d, 0xbb, 0x32, 0x8b, 0xe3, 0x94, 0x4f, 0xbe, 0x1b, 0x21, 0xf9, 0xcc,
            0x23, 0x73, 0x41, 0xb6, 0xb9, 0xb6, 0x98, 0xd0, 0xbc, 0x3a, 0x00, 0x47,
            0x44, 0x56, 0x41, 0x00, 0x3a, 0x00, 0x47, 0x44, 0x57, 0x58, 0x2d, 0xa5,
            0x01, 0x01, 0x03, 0x27, 0x04, 0x81, 0x02, 0x20, 0x06, 0x21, 0x58, 0x20,
            0x5a, 0x39, 0x49, 0x67, 0x8c, 0xd3, 0x0e, 0x88, 0xab, 0x1c, 0xdd, 0xf7,
            0x15, 0x55, 0xd5, 0xbf, 0xd3, 0xf0, 0xb8, 0x47, 0x25, 0xa9, 0x58, 0xe1,
            0xb9, 0xda, 0x4e, 0xb5, 0xf1, 0x38, 0x9a, 0x5a, 0x3a, 0x00, 0x47, 0x44,
            0x58, 0x41, 0x20, 0x58, 0x40, 0x82, 0x99, 0xff, 0x84, 0x55, 0xcb, 0xf9,
            0x99, 0x89, 0x48, 0x99, 0x12, 0x1d, 0x04, 0x40, 0xcf, 0x90, 0xa4, 0xbc,
            0x61, 0x4f, 0x0d, 0x2e, 0x77, 0x2e, 0x9c, 0x8f, 0xaa, 0xdd, 0xf4, 0x2f,
            0xe2, 0x14, 0xd2, 0x42, 0x4a, 0x02, 0x9e, 0x1d, 0x24, 0x72, 0x0b, 0x08,
            0xb6, 0x71, 0xc7, 0x76, 0x64, 0x25, 0xfb, 0x03, 0xcf, 0xd6, 0x6f, 0x2f,
            0x9a, 0x15, 0xc8, 0xad, 0x47, 0x9a, 0xf3, 0x16, 0x01];

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
        let mut certificate_buffer = vec![0u8; 1024]; // Adjust size as needed
        let input_cdi: [u8; DICE_CDI_SIZE] = [0; DICE_CDI_SIZE];
        let input_seal: [u8; DICE_CDI_SIZE] = [0; DICE_CDI_SIZE];
        let next_cdi = dice::generate_next_layer_cdi(&input_cdi, &input_seal, &input_values.code_hash, &input_values.config_value, &input_values.authority_hash, &[0 as u8; 1], &input_values.hidden);

        let cert_len = match dice_generate_certificate(
            &next_cdi.0,
            &input_cdi,
            &input_values,
            &mut certificate_buffer,
        ) {
            Ok(certificate_size) => {
                println!("Certificate generated, size: {}", certificate_size);
                certificate_size
            }
            Err(result) => {
                println!("Failed to generate certificate: {:?}", result);
                0
            }
        };
        for i in &certificate_buffer[..cert_len] {
            print!("{:02X}", i);
        }
        println!();
        for i in &expected_output {
            print!("{:02X}", i);
        }
        println!();
        debug_assert_eq!(cert_len, expected_output.len(), "Does not match expected len");
        debug_assert_eq!(certificate_buffer.as_slice()[..cert_len], expected_output, "Does not match expected value");

        
    }
}
