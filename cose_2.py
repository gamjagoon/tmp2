import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib

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
DICE_PROFILE_NAME = None

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

# Structure
class DiceInputValues:
    def __init__(self, code_hash, code_descriptor, config_type, config_value, config_descriptor,
                 authority_hash, authority_descriptor, mode, hidden):
        self.code_hash = code_hash
        self.code_descriptor = code_descriptor
        self.code_descriptor_size = len(code_descriptor) if code_descriptor else 0
        self.config_type = config_type
        self.config_value = config_value
        self.config_descriptor = config_descriptor
        self.config_descriptor_size = len(config_descriptor) if config_descriptor else 0
        self.authority_hash = authority_hash
        self.authority_descriptor = authority_descriptor
        self.authority_descriptor_size = len(authority_descriptor) if authority_descriptor else 0
        self.mode = mode
        self.hidden = hidden

# Hex encoding function
def DiceHexEncode(data):
    return data.hex()

# COSE encoding function
def DiceCoseEncodePublicKey(public_key):
    cose_key = {
        1: 1,  # Key type: OKP
        3: DICE_COSE_KEY_ALG_VALUE,  # Algorithm: EdDSA
        4: [2],  # Key operations: verify
        -1: 6,  # Curve: Ed25519
        -2: public_key  # Public key
    }
    return cbor2.dumps(cose_key)

# Protected attributes encoding function
def EncodeProtectedAttributes():
    protected_attributes = {1: DICE_COSE_KEY_ALG_VALUE}
    return cbor2.dumps(protected_attributes)

# COSE TBS encoding function
def EncodeCoseTbs(protected_attributes, payload, aad):
    tbs = [
        "Signature1",
        protected_attributes,
        aad,
        payload
    ]
    return cbor2.dumps(tbs)

# COSE Sign1 encoding function
def EncodeCoseSign1(protected_attributes, payload, signature):
    sign1 = [
        protected_attributes,
        {},  # Unprotected attributes
        payload,
        signature
    ]
    return cbor2.dumps(sign1)

# Certificate generation function
def DiceGenerateCertificate(subject_private_key_seed, authority_private_key_seed, input_values):
    try:
        # Derive subject and authority key pairs
        subject_private_key = Ed25519PrivateKey.from_private_bytes(subject_private_key_seed)
        subject_public_key = subject_private_key.public_key().public_bytes(encoding=None, format=None)

        authority_private_key = Ed25519PrivateKey.from_private_bytes(authority_private_key_seed)
        authority_public_key = authority_private_key.public_key().public_bytes(encoding=None, format=None)

        subject_id = hashlib.sha1(subject_public_key).digest()[:DICE_ID_SIZE]
        authority_id = hashlib.sha1(authority_public_key).digest()[:DICE_ID_SIZE]

        subject_id_hex = DiceHexEncode(subject_id)
        authority_id_hex = DiceHexEncode(authority_id)

        encoded_public_key = DiceCoseEncodePublicKey(subject_public_key)

        protected_attributes = EncodeProtectedAttributes()

        cwt = {
            1: authority_id_hex,
            2: subject_id_hex,
            -4670545: input_values.code_hash,
            -4670546: input_values.code_descriptor,
            -4670547: input_values.config_value,
            -4670549: input_values.authority_hash,
            -4670551: input_values.mode.to_bytes(1, 'big'),
            -4670552: encoded_public_key,
            -4670553: bytes([32]),  # Key usage: cert sign
        }

        cwt_bytes = cbor2.dumps(cwt)

        tbs = EncodeCoseTbs(protected_attributes, cwt_bytes, b'')

        signature = authority_private_key.sign(tbs)

        certificate = EncodeCoseSign1(protected_attributes, cwt_bytes, signature)
        return DiceResult.Ok, certificate
    except Exception as e:
        return DiceResult.PlatformError, str(e)

# Example usage
input_values = DiceInputValues(
    code_hash=b'\x00' * DICE_HASH_SIZE,
    code_descriptor=b'Example Code Descriptor',
    config_type=DiceConfigType.Inline,
    config_value=b'\x00' * DICE_INLINE_CONFIG_SIZE,
    config_descriptor=None,
    authority_hash=b'\x00' * DICE_HASH_SIZE,
    authority_descriptor=None,
    mode=DiceMode.Normal,
    hidden=b'\x00' * DICE_HIDDEN_SIZE
)

subject_private_key_seed = b'\x01' * DICE_PRIVATE_KEY_SEED_SIZE
authority_private_key_seed = b'\x02' * DICE_PRIVATE_KEY_SEED_SIZE

result, certificate = DiceGenerateCertificate(subject_private_key_seed, authority_private_key_seed, input_values)
if result == DiceResult.Ok:
    print("Certificate generated successfully.")
    print(certificate.hex())
else:
    print("Error generating certificate:", certificate)
