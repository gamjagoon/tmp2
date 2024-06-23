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

위 코드를 minicbor을 사용한 rust 코드로 작성해줘
