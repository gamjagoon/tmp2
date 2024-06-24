using ScopedCbor = std::unique_ptr<cn_cbor, CborDeleter>;

ScopedCbor ExtractCwtFromCborCertificate(const uint8_t* certificate,
                                         size_t certificate_size) {
  cn_cbor_errback error;
  ScopedCbor sign1(cn_cbor_decode(certificate, certificate_size, &error));
  if (!sign1 || sign1->type != CN_CBOR_ARRAY || sign1->length != 4) {
    return nullptr;
  }
  cn_cbor* payload = cn_cbor_index(sign1.get(), 2);
  if (!payload || payload->type != CN_CBOR_BYTES) {
    return nullptr;
  }
  ScopedCbor cwt(cn_cbor_decode(payload->v.bytes, payload->length, &error));
  if (!cwt || cwt->type != CN_CBOR_MAP) {
    return nullptr;
  }
  return cwt;
}

ScopedCbor ExtractPublicKeyFromCwt(const cn_cbor* cwt) {
  cn_cbor_errback error;
  cn_cbor* key_bytes = cn_cbor_mapget_int(cwt, -4670552);
  if (!key_bytes || key_bytes->type != CN_CBOR_BYTES) {
    return nullptr;
  }
  ScopedCbor key(cn_cbor_decode(key_bytes->v.bytes, key_bytes->length, &error));
  if (key && key->type != CN_CBOR_MAP) {
    return nullptr;
  }
  return key;
}

bool ExtractIdsFromCwt(const cn_cbor* cwt, char authority_id_hex[40],
                       char subject_id_hex[40]) {
  cn_cbor* authority_id_cbor = cn_cbor_mapget_int(cwt, 1);
  cn_cbor* subject_id_cbor = cn_cbor_mapget_int(cwt, 2);
  if (!authority_id_cbor || !subject_id_cbor) {
    return false;
  }
  if (authority_id_cbor->type != CN_CBOR_TEXT ||
      authority_id_cbor->length != 40 ||
      subject_id_cbor->type != CN_CBOR_TEXT || subject_id_cbor->length != 40) {
    return false;
  }
  memcpy(authority_id_hex, authority_id_cbor->v.str, 40);
  memcpy(subject_id_hex, subject_id_cbor->v.str, 40);
  return true;
}

bool ExtractKeyUsageFromCwt(const cn_cbor* cwt, uint64_t* key_usage) {
  cn_cbor* key_usage_bytes = cn_cbor_mapget_int(cwt, -4670553);
  if (!key_usage_bytes || key_usage_bytes->type != CN_CBOR_BYTES) {
    return false;
  }
  // The highest key usage bit defined in RFC 5280 is 8.
  if (key_usage_bytes->length > 2) {
    return false;
  }
  if (key_usage_bytes->length == 0) {
    *key_usage = 0;
    return true;
  }
  *key_usage = key_usage_bytes->v.bytes[0];
  if (key_usage_bytes->length == 2) {
    uint64_t tmp = key_usage_bytes->v.bytes[1];
    *key_usage += tmp >> 8;
  }
  return true;
}


bool ValidateCborCertificateCdiFields(const cn_cbor* cwt,
                                      bool expect_cdi_certificate) {
  cn_cbor* code_hash_bytes = cn_cbor_mapget_int(cwt, -4670545);
  cn_cbor* code_desc_bytes = cn_cbor_mapget_int(cwt, -4670546);
  cn_cbor* conf_hash_bytes = cn_cbor_mapget_int(cwt, -4670547);
  cn_cbor* conf_desc_bytes = cn_cbor_mapget_int(cwt, -4670548);
  cn_cbor* auth_hash_bytes = cn_cbor_mapget_int(cwt, -4670549);
  cn_cbor* auth_desc_bytes = cn_cbor_mapget_int(cwt, -4670550);
  cn_cbor* mode_bytes = cn_cbor_mapget_int(cwt, -4670551);
  if (!expect_cdi_certificate) {
    return (!code_hash_bytes && !code_desc_bytes && !conf_hash_bytes &&
            !conf_desc_bytes && !auth_hash_bytes && !auth_desc_bytes &&
            !mode_bytes);
  }
  if (!code_hash_bytes || !conf_desc_bytes || !auth_hash_bytes || !mode_bytes) {
    return false;
  }
  if (code_hash_bytes->length != 64) {
    return false;
  }
  if (conf_hash_bytes) {
    if (conf_hash_bytes->length != 64) {
      return false;
    }
  } else if (conf_desc_bytes->length != 64) {
    return false;
  }
  if (auth_hash_bytes->length != 64) {
    return false;
  }
  if (mode_bytes->length != 1) {
    return false;
  }
  return true;
}

bool VerifyCoseSign1Signature(const uint8_t* certificate,
                              size_t certificate_size,
                              const uint8_t* external_aad,
                              size_t external_aad_size,
                              const cn_cbor* authority_public_key) {
  // Use the COSE-C library to decode and validate.
  cose_errback error;
  int struct_type = 0;
  HCOSE_SIGN1 sign1 = (HCOSE_SIGN1)COSE_Decode(
      certificate, certificate_size, &struct_type, COSE_sign1_object, &error);
  if (!sign1) {
    return false;
  }
  COSE_Sign1_SetExternal(sign1, external_aad, external_aad_size, &error);
  bool result = COSE_Sign1_validate(sign1, authority_public_key, &error);
  COSE_Sign1_Free(sign1);
  if (!result) {
    return false;
  }
  return true;
}


bool VerifySingleCborCertificate(const uint8_t* certificate,
                                 size_t certificate_size,
                                 const cn_cbor* authority_public_key,
                                 const char authority_id_hex[40],
                                 bool expect_cdi_certificate,
                                 ScopedCbor* subject_public_key,
                                 char subject_id_hex[40]) {
  if (!VerifyCoseSign1Signature(certificate, certificate_size, /*aad=*/NULL,
                                /*aad_size=*/0, authority_public_key)) {
    return false;
  }

  ScopedCbor cwt(ExtractCwtFromCborCertificate(certificate, certificate_size));
  if (!cwt) {
    return false;
  }
  char actual_authority_id[40];
  char tmp_subject_id_hex[40];
  if (!ExtractIdsFromCwt(cwt.get(), actual_authority_id, tmp_subject_id_hex)) {
    return false;
  }
  if (0 != memcmp(authority_id_hex, actual_authority_id, 40)) {
    return false;
  }
  memcpy(subject_id_hex, tmp_subject_id_hex, 40);
  *subject_public_key = ExtractPublicKeyFromCwt(cwt.get());
  if (!subject_public_key) {
    return false;
  }
  uint64_t key_usage = 0;
  const uint64_t kKeyUsageCertSign = 1 << 5;  // Bit 5.
  if (!ExtractKeyUsageFromCwt(cwt.get(), &key_usage)) {
    return false;
  }
  if (key_usage != kKeyUsageCertSign) {
    return false;
  }
  if (!ValidateCborCertificateCdiFields(cwt.get(), expect_cdi_certificate)) {
    return false;
  }
  return true;
}

bool VerifyCborCertificateChain(const uint8_t* root_certificate,
                                size_t root_certificate_size,
                                const dice::test::DiceStateForTest states[],
                                size_t num_dice_states, bool is_partial_chain) {
  ScopedCbor root_cwt =
      ExtractCwtFromCborCertificate(root_certificate, root_certificate_size);
  if (!root_cwt) {
    return false;
  }
  ScopedCbor authority_public_key = ExtractPublicKeyFromCwt(root_cwt.get());
  if (!authority_public_key) {
    return false;
  }
  char expected_authority_id_hex[40];
  char not_used[40];
  if (!ExtractIdsFromCwt(root_cwt.get(), not_used, expected_authority_id_hex)) {
    return false;
  }
  if (!is_partial_chain) {
    // We can't verify the root certificate in a partial chain, we can only
    // check that its public key certifies the other certificates. But with a
    // full chain, we can expect the root to be self-signed.
    if (!VerifySingleCborCertificate(
            root_certificate, root_certificate_size, authority_public_key.get(),
            expected_authority_id_hex, /*expect_cdi_certificate=*/false,
            &authority_public_key, expected_authority_id_hex)) {
      return false;
    }
  }
  for (size_t i = 0; i < num_dice_states; ++i) {
    if (!VerifySingleCborCertificate(
            states[i].certificate, states[i].certificate_size,
            authority_public_key.get(), expected_authority_id_hex,
            /*expect_cdi_certificate=*/true, &authority_public_key,
            expected_authority_id_hex)) {
      return false;
    }
  }
  return true;
}
