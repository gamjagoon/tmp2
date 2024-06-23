```py
import cbor2
import unittest
import hashlib
import util
from dice import CDI

# Constants
DICE_CDI_SIZE = 32
DICE_HASH_SIZE = 64
DICE_HIDDEN_SIZE = 64
DICE_INLINE_CONFIG_SIZE = 64
DICE_PRIVATE_KEY_SEED_SIZE = 32
DICE_ID_SIZE = 20
DICE_PUBLIC_KEY_SIZE = 32
DICE_PRIVATE_KEY_SIZE = 32
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


# Hex encoding function
def DiceHexEncode(data):
    return data.hex()


# COSE encoding function
def DiceCoseEncodePublicKey(public_key) -> bytes:
    cose_key = {
        1: 1,  # Key type: OKP
        3: DICE_COSE_KEY_ALG_VALUE,  # Algorithm: EdDSA
        4: [2],  # Key operations: verify
        -1: 6,  # Curve: Ed25519
        -2: public_key,  # Public key
    }
    return cbor2.dumps(cose_key)


# Protected attributes encoding function
def EncodeProtectedAttributes() -> bytes:
    protected_attributes = {1: DICE_COSE_KEY_ALG_VALUE}
    return cbor2.dumps(protected_attributes)


def EncodeCwt(input_values, authority_id_hex, subject_id_hex, encoded_public_key):
    cwt_map = {
        1: authority_id_hex,  # issuer
        2: subject_id_hex,  # subject
        -4670545: input_values["code_hash"],  # code hash
        -4670549: input_values["authority_hash"],
        -4670551: input_values["mode"],  # mode
        -4670552: encoded_public_key,  # subject public key
        -4670553: 32,  # key usage
    }

    # if provided Add code descriptor
    if input_values["code_descriptor_size"] > 0:
        cwt_map[-4670546] = input_values["code_descriptor"]

    # Add config inputs
    if input_values["config_type"] == "descriptor":
        config_hash = hashlib.sha512(input_values["config_descriptor"]).digest()
        # Add config decriptor
        cwt_map[-4670548] = input_values["config_descriptor"]
        # Add the Config Hash
        cwt_map[-4670547] = config_hash
    else:
        # Add inline config
        cwt_map[-4670548] = input_values["config_value"]

    # Add authority descriptor
    if input_values["authority_descriptor_size"] > 0:
        cwt_map[-4670550] = input_values["authority_descriptor"]

    if DICE_PROFILE_NAME is not None:
        cwt_map[-4670554] = DICE_PROFILE_NAME

    return cbor2.dumps(cwt_map)


# COSE TBS encoding function
def EncodeCoseTbs(protected_attributes, payload, aad) -> bytes:
    tbs = ["Signature1", protected_attributes, aad, payload]
    return cbor2.dumps(tbs)


# COSE Sign1 encoding function
def EncodeCoseSign1(protected_attributes, payload, signature) -> bytes:
    sign1 = [protected_attributes, {}, payload, signature]  # Unprotected attributes
    return cbor2.dumps(sign1)


# Certificate generation function
def DiceGenerateCertificate(next_cdi_attest, current_cdi_attest, input_values):
    """
    next_cdi_attest : generate current layer, gen_cdi_attest(current_cdi_attest, input_values)
    current_cdi_attest : input from prev layer
    input_values : code, config, authority, mode, hidden
    """
    try:
        cdi = CDI()
        subject_private_key, subject_public_key = cdi.asyn_kdf(next_cdi_attest)
        authority_private_key, authority_public_key = cdi.asyn_kdf(current_cdi_attest)

        subject_id = cdi.gen_id(subject_public_key)
        authority_id = cdi.gen_id(authority_public_key)

        subject_id_hex = DiceHexEncode(subject_id)
        authority_id_hex = DiceHexEncode(authority_id)

        encoded_public_key = DiceCoseEncodePublicKey(subject_public_key)

        protected_attributes = EncodeProtectedAttributes()

        cwt_bytes = EncodeCwt(
            input_values, authority_id_hex, subject_id_hex, encoded_public_key
        )

        tbs = EncodeCoseTbs(protected_attributes, cwt_bytes, b"")

        signature = cdi.ed25519_sign(authority_private_key, tbs)

        certificate = EncodeCoseSign1(protected_attributes, cwt_bytes, signature)
        return DiceResult.Ok, certificate
    except Exception as e:
        return DiceResult.PlatformError, str(e)


class DiceOpsTest(unittest.TestCase):

    def setUp(self):
        self.current_state = {
            "cdi_attest": b"\x00" * DICE_CDI_SIZE,
            "cdi_seal": b"\x00" * DICE_CDI_SIZE,
            "certificate": b"\x00"
            * 1000,  # Assuming 1000 bytes for the certificate buffer
            "certificate_size": 0,
        }
        self.next_state = {
            "cdi_attest": b"\x00" * DICE_CDI_SIZE,
            "cdi_seal": b"\x00" * DICE_CDI_SIZE,
            "certificate": b"\x00"
            * 1000,  # Assuming 1000 bytes for the certificate buffer
            "certificate_size": 0,
        }

    def test_known_answer_zero_input(self):
        input_values = {
            "code_hash": b"\x00" * DICE_HASH_SIZE,
            "code_descriptor": b"",
            "code_descriptor_size": len(b""),
            "config_type": "inline",
            "config_value": b"\x00" * DICE_INLINE_CONFIG_SIZE,
            "config_descriptor": b"",
            "config_descriptor_size": len(b""),
            "authority_hash": b"\x00" * DICE_HASH_SIZE,
            "authority_descriptor": b"",
            "authority_descriptor_size": len(b""),
            "mode": 0,
            "hidden": b"\x00" * DICE_HIDDEN_SIZE,
        }

        cdi = CDI()

        cdi.gen_next_cdi_attest_seal(input_values["code_hash"])
        self.next_state["cdi_attest"] = cdi.cdi_attest
        self.next_state["cdi_seal"] = cdi.cdi_seal

        result, certificate = DiceGenerateCertificate(
            cdi.cdi_attest, cdi.prev_cdi_attest, input_values
        )
        print("certificate:",certificate)
        print("kExpectedCborEd25519Cert_ZeroInput:",kExpectedCborEd25519Cert_ZeroInput)
        self.assertEqual(result, DiceResult.Ok)
        self.assertEqual(self.next_state["cdi_attest"], kExpectedCdiAttest_ZeroInput)
        self.assertEqual(self.next_state["cdi_seal"], kExpectedCdiSeal_ZeroInput)
        self.assertEqual(certificate, kExpectedCborEd25519Cert_ZeroInput)
        self.assertEqual(len(certificate), len(kExpectedCborEd25519Cert_ZeroInput))


if __name__ == "__main__":
    unittest.main()
```

certificate:b"\x84C\xa1\x01'\xa0Y\x01m\xa8\x01x(7a06eee41b789f4863d86b8778b1a201a6fedd56\x02x(e7c22a8859062b986818e8e72b0bcd9f59349c89:\x00GDPX@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00:\x00GDTX@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00:\x00GDV\x00:\x00GDWX-\xa5\x01\x01\x03'\x04\x81\x02 \x06!X \r\x14\xe5\xde).\xb1\xc8\xb3\x1b\xea\xe4:\xb5]\x8e\x9d\xc0\x14\xb7>\xaa\x83\xb9%\xa0x\x8c\xc6.\\\x8d:\x00GDX\x18 :\x00GDSX@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00X@\xab\xb9n\x875F\x12ks\xda?~\x0e\n\xd4J\xfd\xb2\x197\x08\x12\xe4W\x08\x07\x9f%P\xb0\x95:\xa4\xf6X\xf8-50\xc3\xb9F\xdc\x19ke\x86\xb1I\xcc\xdc\x0b<<\xc2\x13\x1c\xf8\xce\xeb\xde=t\x05"
kExpectedCborEd25519Cert_ZeroInput:b'\x84C\xa1\x01\'\xa0Y\x01n\xa8\x01x(7a06eee41b789f4863d86b8778b1a201a6fedd56\x02x(67c22a8859062b986818e8e72b0bcd9f59349c89:\x00GDPX@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00:\x00GDSX@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00:\x00GDTX@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00:\x00GDVA\x00:\x00GDWX-\xa5\x01\x01\x03\'\x04\x81\x02 \x06!X \r\x14\xe5\xde).\xb1\xc8\xb3\x1b\xea\xe4:\xb5]\x8e\x9d\xc0\x14\xb7>\xaa\x83\xb9%\xa0x\x8c\xc6.\\\x8d:\x00GDXA X@\xf9\x9b\xd6\xdb\xc1$qS\xc1\x0f\x88\x1c\x0f_3\xbf\x02#\xd2"2q$A\xb1(\xd3\x83\xde2\x1bg\xc0\x9a\x1fE\x91\xc4 \xdc\xc9\xd6!!\xec\xa3\xd3\x89z$M\xcb\xe1\x1a\x0f\x9a\xb7\x9fg\t?\xeeV\x0f'

======================================================================
FAIL: test_known_answer_zero_input (__main__.DiceOpsTest)
----------------------------------------------------------------------
Traceback (most recent call last):
  File ".\test.py", line 726, in test_known_answer_zero_input
    self.assertEqual(certificate, kExpectedCborEd25519Cert_ZeroInput)
AssertionError: b"\x84C\xa1\x01'\xa0Y\x01m\xa8\x01x(7a06ee[1227 chars]\x05" != b'\x84C\xa1\x01\'\xa0Y\x01n\xa8\x01x(7a06e[1230 chars]\x0f'

----------------------------------------------------------------------
Ran 1 test in 0.092s

FAILED (failures=1)

위 코드의 unit 테스트 실행결과가 다음과 같아 두 입출력을 비교해서 틀린점을 확인해줘 내가 분석한 결과는 EncodeCwt 이부분이 이상한거 같아
