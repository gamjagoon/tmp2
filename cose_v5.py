import struct

# Constants per RFC 8152
kCoseKeyKtyLabel = 1
kCoseKeyAlgLabel = 3
kCoseKeyOpsLabel = 4
kCoseOkpCrvLabel = -1
kCoseOkpXLabel = -2
kCoseKeyTypeOkp = 1
kCoseAlgEdDSA = -8  # DICE_COSE_KEY_ALG_VALUE placeholder
kCoseKeyOpsVerify = 2
kCoseCrvEd25519 = 6
DICE_PUBLIC_KEY_SIZE = 32  # Placeholder for the size of the public key

# Result codes
kDiceResultOk = 0
kDiceResultBufferTooSmall = 1
kDiceResultPlatformError = 2
kDiceResultInvalidInput = 3


def CborOutInit(buffer, buffer_size):
    return CborOut(buffer_size)


def CborWriteMap(num_pairs, out):
    out.CborWriteMap(num_pairs)


def CborWriteInt(val, out):
    out.CborWriteInt(val)


def CborWriteArray(num_elements, out):
    out.CborWriteArray(num_elements)


def CborWriteBstr(data_size, data, out):
    out.CborWriteBstr(data[:data_size])


def CborWriteTstr(string, out):
    out.CborWriteTstr(string)


def CborOutSize(out):
    return out.CborOutSize()


def CborOutOverflowed(out):
    return out.CborOutOverflowed()


def CborAllocBstr(data_size, out):
    return out.CborAllocBstr(data_size)


def CborWriteFalse(out):
    out.CborWriteFalse()


def CborWriteTrue(out):
    out.CborWriteTrue()


def CborWriteNull(out):
    out.CborWriteNull()


def DiceHexEncode(in_bytes, num_bytes):
    hex_map = "0123456789abcdef"
    out = ''.join(hex_map[b >> 4] + hex_map[b & 0xF] for b in in_bytes[:num_bytes])
    return out


def DiceCoseEncodePublicKey(context_not_used, public_key, buffer_size, buffer):
    out = CborOut(buffer_size)
    CborWriteMap(5, out)
    CborWriteInt(kCoseKeyKtyLabel, out)
    CborWriteInt(kCoseKeyTypeOkp, out)
    CborWriteInt(kCoseKeyAlgLabel, out)
    CborWriteInt(kCoseAlgEdDSA, out)
    CborWriteInt(kCoseKeyOpsLabel, out)
    CborWriteArray(1, out)
    CborWriteInt(kCoseKeyOpsVerify, out)
    CborWriteInt(kCoseOkpCrvLabel, out)
    CborWriteInt(kCoseCrvEd25519, out)
    CborWriteInt(kCoseOkpXLabel, out)
    CborWriteBstr(DICE_PUBLIC_KEY_SIZE, public_key, out)

    encoded_size = CborOutSize(out)
    if CborOutOverflowed(out):
        return kDiceResultBufferTooSmall, 0
    return kDiceResultOk, encoded_size


def EncodeProtectedAttributes(buffer_size):
    out = CborOut(buffer_size)
    CborWriteMap(1, out)
    CborWriteInt(kCoseKeyAlgLabel, out)
    CborWriteInt(kCoseAlgEdDSA, out)

    encoded_size = CborOutSize(out)
    if CborOutOverflowed(out):
        return kDiceResultBufferTooSmall, 0
    return kDiceResultOk, encoded_size


def EncodeCoseTbs(protected_attributes, protected_attributes_size, payload_size, aad, aad_size, buffer_size):
    out = CborOut(buffer_size)
    CborWriteArray(4, out)
    CborWriteTstr("Signature1", out)
    CborWriteBstr(protected_attributes_size, protected_attributes, out)
    CborWriteBstr(aad_size, aad, out)
    payload = CborAllocBstr(payload_size, out)

    encoded_size = CborOutSize(out)
    if CborOutOverflowed(out):
        return kDiceResultBufferTooSmall, None, 0
    return kDiceResultOk, payload, encoded_size


def EncodeCoseSign1(protected_attributes, protected_attributes_size, payload, payload_size, move_payload, signature, buffer_size):
    out = CborOut(buffer_size)
    CborWriteArray(4, out)
    CborWriteBstr(protected_attributes_size, protected_attributes, out)
    CborWriteMap(0, out)
    if move_payload:
        payload_alloc = CborAllocBstr(payload_size, out)
        if payload_alloc:
            if payload < payload_alloc:
                return kDiceResultPlatformError, 0
            out.buffer[payload_alloc:payload_alloc + payload_size] = out.buffer[payload:payload + payload_size]
    else:
        CborWriteBstr(payload_size, payload, out)
    CborWriteBstr(DICE_SIGNATURE_SIZE, signature, out)

    encoded_size = CborOutSize(out)
    if CborOutOverflowed(out):
        return kDiceResultBufferTooSmall, 0
    return kDiceResultOk, encoded_size


def EncodeCwt(context, input_values, authority_id_hex, subject_id_hex, encoded_public_key, encoded_public_key_size, buffer_size):
    kCwtIssuerLabel = 1
    kCwtSubjectLabel = 2
    kCodeHashLabel = -4670545
    kCodeDescriptorLabel = -4670546
    kConfigHashLabel = -4670547
    kConfigDescriptorLabel = -4670548
    kAuthorityHashLabel = -4670549
    kAuthorityDescriptorLabel = -4670550
    kModeLabel = -4670551
    kSubjectPublicKeyLabel = -4670552
    kKeyUsageLabel = -4670553
    kProfileNameLabel = -4670554
    kKeyUsageCertSign = 32

    map_pairs = 7
    if input_values['code_descriptor_size'] > 0:
        map_pairs += 1
    if input_values['config_type'] == 'descriptor':
        map_pairs += 2
    else:
        map_pairs += 1
    if input_values['authority_descriptor_size'] > 0:
        map_pairs += 1
    if DICE_PROFILE_NAME:
        map_pairs += 1

    out = CborOut(buffer_size)
    CborWriteMap(map_pairs, out)
    CborWriteInt(kCwtIssuerLabel, out)
    CborWriteTstr(authority_id_hex, out)
    CborWriteInt(kCwtSubjectLabel, out)
    CborWriteTstr(subject_id_hex, out)
    CborWriteInt(kCodeHashLabel, out)
    CborWriteBstr(len(input_values['code_hash']), input_values['code_hash'], out)
    if input_values['code_descriptor_size'] > 0:
        CborWriteInt(kCodeDescriptorLabel, out)
        CborWriteBstr(input_values['code_descriptor_size'], input_values['code_descriptor'], out)

    if input_values['config_type'] == 'descriptor':
        config_descriptor_hash = DiceHash(input_values['config_descriptor'], input_values['config_descriptor_size'])
        CborWriteInt(kConfigDescriptorLabel, out)
        CborWriteBstr(input_values['config_descriptor_size'], input_values['config_descriptor'], out)
        CborWriteInt(kConfigHashLabel, out)
        CborWriteBstr(len(config_descriptor_hash), config_descriptor_hash, out)
    else:
        CborWriteInt(kConfigDescriptorLabel, out)
        CborWriteBstr(len(input_values['config_value']), input_values['config_value'], out)

    CborWriteInt(kAuthorityHashLabel, out)
    CborWriteBstr(len(input_values['authority_hash']), input_values['authority_hash'], out)
    if input_values['authority_descriptor_size'] > 0:
        CborWriteInt(kAuthorityDescriptorLabel, out)
        CborWriteBstr(input_values['authority_descriptor_size'], input_values['authority_descriptor'], out)

    mode_byte = input_values['mode']
    key_usage = kKeyUsageCertSign
    CborWriteInt(kModeLabel, out)
    CborWriteBstr(1, bytes([mode_byte]), out)
    CborWriteInt(kSubjectPublicKeyLabel, out)
    CborWriteBstr(encoded_public_key_size, encoded_public_key, out)
    CborWriteInt(kKeyUsageLabel, out)
    CborWriteBstr(1, bytes([key_usage]), out)
    if DICE_PROFILE_NAME:
        CborWriteInt(kProfileNameLabel, out)
        CborWriteTstr(DICE_PROFILE_NAME, out)

    encoded_size = CborOutSize(out)
    if CborOutOverflowed(out):
        return kDiceResultBufferTooSmall, 0
    return kDiceResultOk, encoded_size


def DiceGenerateCertificate(context, subject_private_key_seed, authority_private_key_seed, input_values, certificate_buffer_size):
    certificate = bytearray(certificate_buffer_size)
    certificate_actual_size = 0

    if input_values['config_type'] not in ['descriptor', 'inline']:
        return kDiceResultInvalidInput, 0

    subject_private_key = bytearray(DICE_PRIVATE_KEY_SIZE)
    authority_private_key = bytearray(DICE_PRIVATE_KEY_SIZE)

    subject_public_key = bytearray(DICE_PUBLIC_KEY_SIZE)
    result = DiceKeypairFromSeed(context, subject_private_key_seed, subject_public_key, subject_private_key)
    if result != kDiceResultOk:
        return result, 0

    subject_id = DiceDeriveCdiCertificateId(context, subject_public_key, DICE_PUBLIC_KEY_SIZE)
    subject_id_hex = DiceHexEncode(subject_id, len(subject_id))

    authority_public_key = bytearray(DICE_PUBLIC_KEY_SIZE)
    result = DiceKeypairFromSeed(context, authority_private_key_seed, authority_public_key, authority_private_key)
    if result != kDiceResultOk:
        return result, 0

    authority_id = DiceDeriveCdiCertificateId(context, authority_public_key, DICE_PUBLIC_KEY_SIZE)
    authority_id_hex = DiceHexEncode(authority_id, len(authority_id))

    encoded_public_key = bytearray(DICE_MAX_PUBLIC_KEY_SIZE)
    result, encoded_public_key_size = DiceCoseEncodePublicKey(context, subject_public_key, len(encoded_public_key), encoded_public_key)
    if result != kDiceResultOk:
        return kDiceResultPlatformError, 0

    protected_attributes = bytearray(DICE_MAX_PROTECTED_ATTRIBUTES_SIZE)
    result, protected_attributes_size = EncodeProtectedAttributes(len(protected_attributes))
    if result != kDiceResultOk:
        return kDiceResultPlatformError, 0

    cwt_size = EncodeCwt(context, input_values, authority_id_hex, subject_id_hex, encoded_public_key, encoded_public_key_size, 0)
    result, cwt_ptr, tbs_size = EncodeCoseTbs(protected_attributes, protected_attributes_size, cwt_size, None, 0, certificate_buffer_size)
    if result != kDiceResultOk:
        final_encoded_size = EncodeCoseSign1(protected_attributes, protected_attributes_size, cwt_ptr, cwt_size, False, None, 0)
        certificate_actual_size = max(final_encoded_size, tbs_size)
        return kDiceResultBufferTooSmall, certificate_actual_size

    final_cwt_size = EncodeCwt(context, input_values, authority_id_hex, subject_id_hex, encoded_public_key, encoded_public_key_size, cwt_size, cwt_ptr)
    if final_cwt_size != cwt_size:
        return kDiceResultPlatformError, 0

    signature = DiceSign(context, certificate[:tbs_size], authority_private_key)
    result, certificate_actual_size = EncodeCoseSign1(protected_attributes, protected_attributes_size, cwt_ptr, cwt_size, True, signature, certificate_buffer_size)
    if result != kDiceResultOk:
        return result, 0

    DiceClearMemory(context, subject_private_key)
    DiceClearMemory(context, authority_private_key)

    return kDiceResultOk, certificate_actual_size
