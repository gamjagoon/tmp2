from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import cbor2

# Constants
DICE_CDI_SIZE = 32
DICE_HASH_SIZE = 64
DICE_HIDDEN_SIZE = 64
DICE_INLINE_CONFIG_SIZE = 64
DICE_PRIVATE_KEY_SEED_SIZE = 32
DICE_ID_SIZE = 20
DICE_PUBLIC_KEY_SIZE = 32
DICE_PRIVATE_KEY_SIZE = 64
DICE_SIGNATURE_SIZE = 64
DICE_MAX_PUBLIC_KEY_SIZE = DICE_PUBLIC_KEY_SIZE + 32
DICE_MAX_PROTECTED_ATTRIBUTES_SIZE = 16
DICE_COSE_KEY_ALG_VALUE = -8

# Enums
class DiceResult:
    Ok = 0
    InvalidInput = 1
    BufferTooSmall = 2
    PlatformError = 3

class DiceMode:
    NotInitialized = 0
    Normal = 1
    Debug = 2
    Maintenance = 3

class DiceConfigType:
    Inline = 0
    Descriptor = 1

# Functions for encoding and decoding
def hex_encode(data):
    return data.hex()

def cose_encode_public_key(public_key):
    cose_key = {
        1: 1,  # Key type: OKP
        3: DICE_COSE_KEY_ALG_VALUE,  # Algorithm: EdDSA
        4: [2],  # Key operations: verify
        -1: 6,  # Curve: Ed25519
        -2: public_key  # Public key
    }
    return cbor2.dumps(cose_key)

def encode_protected_attributes():
    protected_attributes = {1: DICE_COSE_KEY_ALG_VALUE}
    return cbor2.dumps(protected_attributes)

def encode_cose_tbs(protected_attributes, payload, aad):
    tbs = [
        "Signature1",
        protected_attributes,
        aad,
        payload
    ]
    return cbor2.dumps(tbs)

def encode_cose_sign1(protected_attributes, payload, signature):
    sign1 = [
        protected_attributes,
        {},  # Unprotected attributes
        payload,
        signature
    ]
    return cbor2.dumps(sign1)

def dice_generate_certificate(subject_private_key_seed, authority_private_key_seed, input_values):
    # Derive subject and authority key pairs
    subject_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(subject_private_key_seed)
    subject_public_key = subject_private_key.public_key().public_bytes()

    authority_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(authority_private_key_seed)
    authority_public_key = authority_private_key.public_key().public_bytes()

    subject_id = hex_encode(subject_public_key[:DICE_ID_SIZE])
    authority_id = hex_encode(authority_public_key[:DICE_ID_SIZE])

    encoded_public_key = cose_encode_public_key(subject_public_key)

    protected_attributes = encode_protected_attributes()

    cwt = {
        1: authority_id,
        2: subject_id,
        -4670545: input_values['code_hash'],
        -4670546: input_values['code_descriptor'],
        -4670547: input_values['config_value'],
        -4670549: input_values['authority_hash'],
        -4670551: input_values['mode'].value.to_bytes(1, 'big'),
        -4670552: encoded_public_key,
        -4670553: bytes([32]),  # Key usage: cert sign
    }

    cwt_bytes = cbor2.dumps(cwt)

    tbs = encode_cose_tbs(protected_attributes, cwt_bytes, b'')

    signature = authority_private_key.sign(tbs)

    certificate = encode_cose_sign1(protected_attributes, cwt_bytes, signature)
    
    return certificate

# Example usage
input_values = {
    'code_hash': b'\x00' * DICE_HASH_SIZE,
    'code_descriptor': b'Example Code Descriptor',
    'config_value': b'\x00' * DICE_INLINE_CONFIG_SIZE,
    'authority_hash': b'\x00' * DICE_HASH_SIZE,
    'mode': DiceMode.Normal
}

subject_private_key_seed = b'\x01' * DICE_PRIVATE_KEY_SEED_SIZE
authority_private_key_seed = b'\x02' * DICE_PRIVATE_KEY_SEED_SIZE

certificate = dice_generate_certificate(subject_private_key_seed, authority_private_key_seed, input_values)
print(certificate.hex())
