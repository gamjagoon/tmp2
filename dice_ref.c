
#define DICE_CDI_SIZE 32
#define DICE_HASH_SIZE 64
#define DICE_HIDDEN_SIZE 64
#define DICE_INLINE_CONFIG_SIZE 64
#define DICE_PRIVATE_KEY_SEED_SIZE 32
#define DICE_ID_SIZE 20
#define DICE_MAX_PUBLIC_KEY_SIZE (DICE_PUBLIC_KEY_SIZE + 32)
#define DICE_MAX_PROTECTED_ATTRIBUTES_SIZE 16
// Ed25519
// COSE Key alg value from Table 2 of RFC9053
#define DICE_COSE_KEY_ALG_VALUE (-8)
#define DICE_PUBLIC_KEY_SIZE 32
#define DICE_PRIVATE_KEY_SIZE 64
#define DICE_SIGNATURE_SIZE 64
#define DICE_PROFILE_NAME NULL
struct CborOut {
  uint8_t* buffer;
  size_t buffer_size;
  size_t cursor;
};

// Initializes an output stream for writing CBOR tokens.
static inline void CborOutInit(uint8_t* buffer, size_t buffer_size,
                               struct CborOut* out) {
  out->buffer = buffer;
  out->buffer_size = buffer_size;
  out->cursor = 0;
}

// Returns the number of bytes of encoded data. If |CborOutOverflowed()|
// returns false, this number of bytes have been written, otherwise, this is the
// number of bytes that that would have been written had there been space.
static inline size_t CborOutSize(const struct CborOut* out) {
  return out->cursor;
}

// Returns whether the |out| buffer contains the encoded tokens written to it or
// whether the encoded tokens did not fit and the contents of the buffer should
// be considered invalid.
static inline bool CborOutOverflowed(const struct CborOut* out) {
  return out->cursor == SIZE_MAX || out->cursor > out->buffer_size;
}
enum CborType {
  CBOR_TYPE_UINT = 0,
  CBOR_TYPE_NINT = 1,
  CBOR_TYPE_BSTR = 2,
  CBOR_TYPE_TSTR = 3,
  CBOR_TYPE_ARRAY = 4,
  CBOR_TYPE_MAP = 5,
  CBOR_TYPE_TAG = 6,
  CBOR_TYPE_SIMPLE = 7,
};

static bool CborWriteWouldOverflowCursor(size_t size, struct CborOut* out) {
  return size > SIZE_MAX - out->cursor;
}

static bool CborWriteFitsInBuffer(size_t size, struct CborOut* out) {
  return out->cursor <= out->buffer_size &&
         size <= out->buffer_size - out->cursor;
}

static void CborWriteType(enum CborType type, uint64_t val,
                          struct CborOut* out) {
  size_t size;
  if (val <= 23) {
    size = 1;
  } else if (val <= 0xff) {
    size = 2;
  } else if (val <= 0xffff) {
    size = 3;
  } else if (val <= 0xffffffff) {
    size = 5;
  } else {
    size = 9;
  }
  if (CborWriteWouldOverflowCursor(size, out)) {
    out->cursor = SIZE_MAX;
    return;
  }
  if (CborWriteFitsInBuffer(size, out)) {
    if (size == 1) {
      out->buffer[out->cursor] = (type << 5) | val;
    } else if (size == 2) {
      out->buffer[out->cursor] = (type << 5) | 24;
      out->buffer[out->cursor + 1] = val & 0xff;
    } else if (size == 3) {
      out->buffer[out->cursor] = (type << 5) | 25;
      out->buffer[out->cursor + 1] = (val >> 8) & 0xff;
      out->buffer[out->cursor + 2] = val & 0xff;
    } else if (size == 5) {
      out->buffer[out->cursor] = (type << 5) | 26;
      out->buffer[out->cursor + 1] = (val >> 24) & 0xff;
      out->buffer[out->cursor + 2] = (val >> 16) & 0xff;
      out->buffer[out->cursor + 3] = (val >> 8) & 0xff;
      out->buffer[out->cursor + 4] = val & 0xff;
    } else if (size == 9) {
      out->buffer[out->cursor] = (type << 5) | 27;
      out->buffer[out->cursor + 1] = (val >> 56) & 0xff;
      out->buffer[out->cursor + 2] = (val >> 48) & 0xff;
      out->buffer[out->cursor + 3] = (val >> 40) & 0xff;
      out->buffer[out->cursor + 4] = (val >> 32) & 0xff;
      out->buffer[out->cursor + 5] = (val >> 24) & 0xff;
      out->buffer[out->cursor + 6] = (val >> 16) & 0xff;
      out->buffer[out->cursor + 7] = (val >> 8) & 0xff;
      out->buffer[out->cursor + 8] = val & 0xff;
    }
  }
  out->cursor += size;
}

static void* CborAllocStr(enum CborType type, size_t data_size,
                          struct CborOut* out) {
  CborWriteType(type, data_size, out);
  bool overflow = CborWriteWouldOverflowCursor(data_size, out);
  bool fit = CborWriteFitsInBuffer(data_size, out);
  void* ptr = (overflow || !fit) ? NULL : &out->buffer[out->cursor];
  out->cursor = overflow ? SIZE_MAX : out->cursor + data_size;
  return ptr;
}

static void CborWriteStr(enum CborType type, size_t data_size, const void* data,
                         struct CborOut* out) {
  uint8_t* ptr = CborAllocStr(type, data_size, out);
  if (ptr && data_size) {
    memcpy(ptr, data, data_size);
  }
}

void CborWriteInt(int64_t val, struct CborOut* out) {
  if (val < 0) {
    CborWriteType(CBOR_TYPE_NINT, (-1 - val), out);
  } else {
    CborWriteType(CBOR_TYPE_UINT, val, out);
  }
}

void CborWriteUint(uint64_t val, struct CborOut* out) {
  CborWriteType(CBOR_TYPE_UINT, val, out);
}

void CborWriteBstr(size_t data_size, const uint8_t* data, struct CborOut* out) {
  CborWriteStr(CBOR_TYPE_BSTR, data_size, data, out);
}

uint8_t* CborAllocBstr(size_t data_size, struct CborOut* out) {
  return CborAllocStr(CBOR_TYPE_BSTR, data_size, out);
}

void CborWriteTstr(const char* str, struct CborOut* out) {
  CborWriteStr(CBOR_TYPE_TSTR, strlen(str), str, out);
}

char* CborAllocTstr(size_t size, struct CborOut* out) {
  return CborAllocStr(CBOR_TYPE_TSTR, size, out);
}

void CborWriteArray(size_t num_elements, struct CborOut* out) {
  CborWriteType(CBOR_TYPE_ARRAY, num_elements, out);
}

void CborWriteMap(size_t num_pairs, struct CborOut* out) {
  CborWriteType(CBOR_TYPE_MAP, num_pairs, out);
}

void CborWriteTag(uint64_t tag, struct CborOut* out) {
  CborWriteType(CBOR_TYPE_TAG, tag, out);
}

void CborWriteFalse(struct CborOut* out) {
  CborWriteType(CBOR_TYPE_SIMPLE, /*val=*/20, out);
}

void CborWriteTrue(struct CborOut* out) {
  CborWriteType(CBOR_TYPE_SIMPLE, /*val=*/21, out);
}

void CborWriteNull(struct CborOut* out) {
  CborWriteType(CBOR_TYPE_SIMPLE, /*val=*/22, out);
}
typedef enum {
  kDiceResultOk,
  kDiceResultInvalidInput,
  kDiceResultBufferTooSmall,
  kDiceResultPlatformError,
} DiceResult;

typedef enum {
  kDiceModeNotInitialized,
  kDiceModeNormal,
  kDiceModeDebug,
  kDiceModeMaintenance,
} DiceMode;

typedef enum {
  kDiceConfigTypeInline,
  kDiceConfigTypeDescriptor,
} DiceConfigType;

typedef struct DiceInputValues_ {
  uint8_t code_hash[DICE_HASH_SIZE];
  const uint8_t* code_descriptor;
  size_t code_descriptor_size;
  DiceConfigType config_type;
  uint8_t config_value[DICE_INLINE_CONFIG_SIZE];
  const uint8_t* config_descriptor;
  size_t config_descriptor_size;
  uint8_t authority_hash[DICE_HASH_SIZE];
  const uint8_t* authority_descriptor;
  size_t authority_descriptor_size;
  DiceMode mode;
  uint8_t hidden[DICE_HIDDEN_SIZE];
} DiceInputValues;

void DiceHexEncode(const uint8_t* in, size_t num_bytes, void* out,
                   size_t out_size) {
  const uint8_t kHexMap[16] = "0123456789abcdef";
  size_t in_pos = 0;
  size_t out_pos = 0;
  uint8_t* out_bytes = out;
  for (in_pos = 0; in_pos < num_bytes && out_pos < out_size; ++in_pos) {
    out_bytes[out_pos++] = kHexMap[(in[in_pos] >> 4)];
    if (out_pos < out_size) {
      out_bytes[out_pos++] = kHexMap[in[in_pos] & 0xF];
    }
  }
}

DiceResult DiceCoseEncodePublicKey(
    void* context_not_used, const uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
    size_t buffer_size, uint8_t* buffer, size_t* encoded_size) {
  (void)context_not_used;

  // Constants per RFC 8152.
  const int64_t kCoseKeyKtyLabel = 1;
  const int64_t kCoseKeyAlgLabel = 3;
  const int64_t kCoseKeyOpsLabel = 4;
  const int64_t kCoseOkpCrvLabel = -1;
  const int64_t kCoseOkpXLabel = -2;
  const int64_t kCoseKeyTypeOkp = 1;
  const int64_t kCoseAlgEdDSA = DICE_COSE_KEY_ALG_VALUE;
  const int64_t kCoseKeyOpsVerify = 2;
  const int64_t kCoseCrvEd25519 = 6;

  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteMap(/*num_pairs=*/5, &out);
  // Add the key type.
  CborWriteInt(kCoseKeyKtyLabel, &out);
  CborWriteInt(kCoseKeyTypeOkp, &out);
  // Add the algorithm.
  CborWriteInt(kCoseKeyAlgLabel, &out);
  CborWriteInt(kCoseAlgEdDSA, &out);
  // Add the KeyOps.
  CborWriteInt(kCoseKeyOpsLabel, &out);
  CborWriteArray(/*num_elements=*/1, &out);
  CborWriteInt(kCoseKeyOpsVerify, &out);
  // Add the curve.
  CborWriteInt(kCoseOkpCrvLabel, &out);
  CborWriteInt(kCoseCrvEd25519, &out);
  // Add the public key.
  CborWriteInt(kCoseOkpXLabel, &out);
  CborWriteBstr(/*data_size=*/DICE_PUBLIC_KEY_SIZE, public_key, &out);

  *encoded_size = CborOutSize(&out);
  if (CborOutOverflowed(&out)) {
    return kDiceResultBufferTooSmall;
  }
  return kDiceResultOk;
}

static DiceResult EncodeProtectedAttributes(size_t buffer_size, uint8_t* buffer,
                                            size_t* encoded_size) {
  // Constants per RFC 8152.
  const int64_t kCoseHeaderAlgLabel = 1;

  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteMap(/*num_elements=*/1, &out);
  CborWriteInt(kCoseHeaderAlgLabel, &out);
  CborWriteInt(DICE_COSE_KEY_ALG_VALUE, &out);
  *encoded_size = CborOutSize(&out);
  if (CborOutOverflowed(&out)) {
    return kDiceResultBufferTooSmall;
  }
  return kDiceResultOk;
}

static DiceResult EncodeCoseTbs(const uint8_t* protected_attributes,
                                size_t protected_attributes_size,
                                size_t payload_size, const uint8_t* aad,
                                size_t aad_size, size_t buffer_size,
                                uint8_t* buffer, uint8_t** payload,
                                size_t* encoded_size) {
  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteArray(/*num_elements=*/4, &out);
  CborWriteTstr("Signature1", &out);
  CborWriteBstr(protected_attributes_size, protected_attributes, &out);
  CborWriteBstr(aad_size, aad, &out);
  *payload = CborAllocBstr(payload_size, &out);
  *encoded_size = CborOutSize(&out);
  if (CborOutOverflowed(&out)) {
    return kDiceResultBufferTooSmall;
  }
  return kDiceResultOk;
}

static DiceResult EncodeCoseSign1(const uint8_t* protected_attributes,
                                  size_t protected_attributes_size,
                                  const uint8_t* payload, size_t payload_size,
                                  bool move_payload,
                                  const uint8_t signature[DICE_SIGNATURE_SIZE],
                                  size_t buffer_size, uint8_t* buffer,
                                  size_t* encoded_size) {
  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteArray(/*num_elements=*/4, &out);
  CborWriteBstr(protected_attributes_size, protected_attributes, &out);
  CborWriteMap(/*num_pairs=*/0, &out);
  if (move_payload) {
    // The payload is already present in the buffer, so we can move it into
    // place.
    uint8_t* payload_alloc = CborAllocBstr(payload_size, &out);
    if (payload_alloc) {
      // We're assuming what we've written above is small enough that it doesn't
      // overwrite the payload. Check in case that stops being true.
      if (payload < payload_alloc) {
        return kDiceResultPlatformError;
      }
      memmove(payload_alloc, payload, payload_size);
    }
  } else {
    CborWriteBstr(payload_size, payload, &out);
  }
  // Signature.
  CborWriteBstr(/*num_elements=*/DICE_SIGNATURE_SIZE, signature, &out);
  *encoded_size = CborOutSize(&out);
  if (CborOutOverflowed(&out)) {
    return kDiceResultBufferTooSmall;
  }
  return kDiceResultOk;
}

// Encodes a CBOR Web Token (CWT) with an issuer, subject, and additional
// fields.
static DiceResult EncodeCwt(void* context, const DiceInputValues* input_values,
                            const char* authority_id_hex,
                            const char* subject_id_hex,
                            const uint8_t* encoded_public_key,
                            size_t encoded_public_key_size, size_t buffer_size,
                            uint8_t* buffer, size_t* encoded_size) {
  // Constants per RFC 8392.
  const int64_t kCwtIssuerLabel = 1;
  const int64_t kCwtSubjectLabel = 2;
  // Constants per the Open Profile for DICE specification.
  const int64_t kCodeHashLabel = -4670545;
  const int64_t kCodeDescriptorLabel = -4670546;
  const int64_t kConfigHashLabel = -4670547;
  const int64_t kConfigDescriptorLabel = -4670548;
  const int64_t kAuthorityHashLabel = -4670549;
  const int64_t kAuthorityDescriptorLabel = -4670550;
  const int64_t kModeLabel = -4670551;
  const int64_t kSubjectPublicKeyLabel = -4670552;
  const int64_t kKeyUsageLabel = -4670553;
  const int64_t kProfileNameLabel = -4670554;
  // Key usage constant per RFC 5280.
  const uint8_t kKeyUsageCertSign = 32;

  // Count the number of entries.
  uint32_t map_pairs = 7;
  if (input_values->code_descriptor_size > 0) {
    map_pairs += 1;
  }
  if (input_values->config_type == kDiceConfigTypeDescriptor) {
    map_pairs += 2;
  } else {
    map_pairs += 1;
  }
  if (input_values->authority_descriptor_size > 0) {
    map_pairs += 1;
  }
  if (DICE_PROFILE_NAME) {
    map_pairs += 1;
  }

  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteMap(map_pairs, &out);
  CborWriteInt(kCwtIssuerLabel, &out);
  CborWriteTstr(authority_id_hex, &out);
  CborWriteInt(kCwtSubjectLabel, &out);
  CborWriteTstr(subject_id_hex, &out);
  CborWriteInt(kCodeHashLabel, &out);
  CborWriteBstr(DICE_HASH_SIZE, input_values->code_hash, &out);
  if (input_values->code_descriptor_size > 0) {
    CborWriteInt(kCodeDescriptorLabel, &out);
    CborWriteBstr(input_values->code_descriptor_size,
                  input_values->code_descriptor, &out);
  }
  // Add the config inputs.
  if (input_values->config_type == kDiceConfigTypeDescriptor) {
    uint8_t config_descriptor_hash[DICE_HASH_SIZE];
    // Skip hashing if we're not going to use the answer.
    if (!CborOutOverflowed(&out)) {
      DiceResult result = DiceHash(context, input_values->config_descriptor,
                                   input_values->config_descriptor_size,
                                   config_descriptor_hash);
      if (result != kDiceResultOk) {
        return result;
      }
    }
    // Add the config descriptor.
    CborWriteInt(kConfigDescriptorLabel, &out);
    CborWriteBstr(input_values->config_descriptor_size,
                  input_values->config_descriptor, &out);
    // Add the Config hash.
    CborWriteInt(kConfigHashLabel, &out);
    CborWriteBstr(DICE_HASH_SIZE, config_descriptor_hash, &out);
  } else if (input_values->config_type == kDiceConfigTypeInline) {
    // Add the inline config.
    CborWriteInt(kConfigDescriptorLabel, &out);
    CborWriteBstr(DICE_INLINE_CONFIG_SIZE, input_values->config_value, &out);
  }
  // Add the authority inputs.
  CborWriteInt(kAuthorityHashLabel, &out);
  CborWriteBstr(DICE_HASH_SIZE, input_values->authority_hash, &out);
  if (input_values->authority_descriptor_size > 0) {
    CborWriteInt(kAuthorityDescriptorLabel, &out);
    CborWriteBstr(input_values->authority_descriptor_size,
                  input_values->authority_descriptor, &out);
  }
  uint8_t mode_byte = input_values->mode;
  uint8_t key_usage = kKeyUsageCertSign;
  // Add the mode input.
  CborWriteInt(kModeLabel, &out);
  CborWriteBstr(/*data_sisze=*/1, &mode_byte, &out);
  // Add the subject public key.
  CborWriteInt(kSubjectPublicKeyLabel, &out);
  CborWriteBstr(encoded_public_key_size, encoded_public_key, &out);
  // Add the key usage.
  CborWriteInt(kKeyUsageLabel, &out);
  CborWriteBstr(/*data_size=*/1, &key_usage, &out);
  // Add the profile name
  if (DICE_PROFILE_NAME) {
    CborWriteInt(kProfileNameLabel, &out);
    CborWriteTstr(DICE_PROFILE_NAME, &out);
  }
  *encoded_size = CborOutSize(&out);
  if (CborOutOverflowed(&out)) {
    return kDiceResultBufferTooSmall;
  }
  return kDiceResultOk;
}

DiceResult DiceGenerateCertificate(
    void* context,
    const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size) {
  DiceResult result = kDiceResultOk;

  *certificate_actual_size = 0;
  if (input_values->config_type != kDiceConfigTypeDescriptor &&
      input_values->config_type != kDiceConfigTypeInline) {
    return kDiceResultInvalidInput;
  }

  // Declare buffers which are cleared on 'goto out'.
  uint8_t subject_private_key[DICE_PRIVATE_KEY_SIZE];
  uint8_t authority_private_key[DICE_PRIVATE_KEY_SIZE];

  // Derive keys and IDs from the private key seeds.
  uint8_t subject_public_key[DICE_PUBLIC_KEY_SIZE];
  result = DiceKeypairFromSeed(context, subject_private_key_seed,
                               subject_public_key, subject_private_key);
  if (result != kDiceResultOk) {
    goto out;
  }

  uint8_t subject_id[DICE_ID_SIZE];
  result = DiceDeriveCdiCertificateId(context, subject_public_key,
                                      DICE_PUBLIC_KEY_SIZE, subject_id);
  if (result != kDiceResultOk) {
    goto out;
  }
  char subject_id_hex[41];
  DiceHexEncode(subject_id, sizeof(subject_id), subject_id_hex,
                sizeof(subject_id_hex));
  subject_id_hex[sizeof(subject_id_hex) - 1] = '\0';

  uint8_t authority_public_key[DICE_PUBLIC_KEY_SIZE];
  result = DiceKeypairFromSeed(context, authority_private_key_seed,
                               authority_public_key, authority_private_key);
  if (result != kDiceResultOk) {
    goto out;
  }

  uint8_t authority_id[DICE_ID_SIZE];
  result = DiceDeriveCdiCertificateId(context, authority_public_key,
                                      DICE_PUBLIC_KEY_SIZE, authority_id);
  if (result != kDiceResultOk) {
    goto out;
  }
  char authority_id_hex[41];
  DiceHexEncode(authority_id, sizeof(authority_id), authority_id_hex,
                sizeof(authority_id_hex));
  authority_id_hex[sizeof(authority_id_hex) - 1] = '\0';

  // The public key encoded as a COSE_Key structure is embedded in the CWT.
  uint8_t encoded_public_key[DICE_MAX_PUBLIC_KEY_SIZE];
  size_t encoded_public_key_size = 0;
  result = DiceCoseEncodePublicKey(
      context, subject_public_key, sizeof(encoded_public_key),
      encoded_public_key, &encoded_public_key_size);
  if (result != kDiceResultOk) {
    result = kDiceResultPlatformError;
    goto out;
  }

  // The encoded protected attributes are used in the TBS and the final
  // COSE_Sign1 structure.
  uint8_t protected_attributes[DICE_MAX_PROTECTED_ATTRIBUTES_SIZE];
  size_t protected_attributes_size = 0;
  result = EncodeProtectedAttributes(sizeof(protected_attributes),
                                     protected_attributes,
                                     &protected_attributes_size);
  if (result != kDiceResultOk) {
    result = kDiceResultPlatformError;
    goto out;
  }

  // Find out how big the CWT will be.
  size_t cwt_size;
  EncodeCwt(context, input_values, authority_id_hex, subject_id_hex,
            encoded_public_key, encoded_public_key_size, /*buffer_size=*/0,
            /*buffer=*/NULL, &cwt_size);

  uint8_t* cwt_ptr;
  size_t tbs_size;
  result =
      EncodeCoseTbs(protected_attributes, protected_attributes_size, cwt_size,
                    /*aad=*/NULL, /*aad_size=*/0, certificate_buffer_size,
                    certificate, &cwt_ptr, &tbs_size);

  if (result != kDiceResultOk) {
    // There wasn't enough space to put together the TBS. The total buffer size
    // we need is either the amount needed for the TBS, or the amount needed for
    // encoded payload and signature.
    size_t final_encoded_size = 0;
    EncodeCoseSign1(protected_attributes, protected_attributes_size, cwt_ptr,
                    cwt_size, /*move_payload=*/false, /*signature=*/NULL,
                    /*buffer_size=*/0, /*buffer=*/NULL, &final_encoded_size);
    *certificate_actual_size =
        final_encoded_size > tbs_size ? final_encoded_size : tbs_size;
    result = kDiceResultBufferTooSmall;
    goto out;
  }

  // Now we can encode the payload directly into the allocated BSTR in the TBS.
  size_t final_cwt_size;
  result = EncodeCwt(context, input_values, authority_id_hex, subject_id_hex,
                     encoded_public_key, encoded_public_key_size, cwt_size,
                     cwt_ptr, &final_cwt_size);
  if (result == kDiceResultBufferTooSmall || final_cwt_size != cwt_size) {
    result = kDiceResultPlatformError;
  }
  if (result != kDiceResultOk) {
    goto out;
  }

  // Sign the now-complete TBS.
  uint8_t signature[DICE_SIGNATURE_SIZE];
  result = DiceSign(context, certificate, tbs_size, authority_private_key,
                    signature);
  if (result != kDiceResultOk) {
    goto out;
  }

  // And now we can produce the complete CoseSign1, including the signature, and
  // moving the payload into place as we do it.
  result = EncodeCoseSign1(protected_attributes, protected_attributes_size,
                           cwt_ptr, cwt_size, /*move_payload=*/true, signature,
                           certificate_buffer_size, certificate,
                           certificate_actual_size);

out:
  DiceClearMemory(context, sizeof(subject_private_key), subject_private_key);
  DiceClearMemory(context, sizeof(authority_private_key),
                  authority_private_key);

  return result;
}
