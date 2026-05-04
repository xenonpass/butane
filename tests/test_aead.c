#include "butane.h"
#include "internal.h"
#include "test_framework.h"
#include <string.h>

// === helpers ===

static butane_t create_ctx_with_derived_key(void) {
  butane_t ctx = butane_init();
  if (!ctx)
    return NULL;

  const uint8_t password[] = "butane-test-password";
  const uint8_t salt[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

  // use fast params for testing
  butane_argon2id_params params;
  butane_argon2id_default_params(&params);
  params.t_cost = 1;
  params.m_cost = 256;
  params.parallelism = 1;

  int ret = butane_derive_key(ctx, password, sizeof(password) - 1, salt,
                              sizeof(salt), &params);
  if (ret != BUTANE_OK) {
    butane_free(ctx);
    return NULL;
  }
  return ctx;
}

// === cipher mode detection ===

static void test_cipher_mode_is_set(void) {
  butane_t ctx = butane_init();
  BT_ASSERT_NOT_NULL(ctx);

  int mode = butane_get_cipher_mode(ctx);
  BT_ASSERT(mode == BUTANE_CIPHER_AES256GCM || mode == BUTANE_CIPHER_XCHACHA20,
            "cipher mode should be aes or chacha");

  butane_free(ctx);
}

static void test_cipher_mode_null_ctx(void) {
  int mode = butane_get_cipher_mode(NULL);
  BT_ASSERT_EQ_INT(mode, 0);
}

// === happy path: encrypt then decrypt ===

static void test_encrypt_decrypt_roundtrip(void) {
  butane_t ctx = create_ctx_with_derived_key();
  BT_ASSERT_NOT_NULL(ctx);

  const uint8_t plaintext[] = "the quick brown fox jumps over the lazy dog";
  size_t plaintext_len = sizeof(plaintext) - 1;

  uint8_t ciphertext[128];
  uint8_t decrypted[128];
  uint8_t nonce[BUTANE_MAX_NONCE_SIZE];
  uint8_t tag[BUTANE_TAG_SIZE];

  int ret =
      butane_encrypt(ctx, plaintext, plaintext_len, ciphertext, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_OK);

  ret = butane_decrypt(ctx, ciphertext, plaintext_len, decrypted, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_OK);
  BT_ASSERT_EQ_MEM(decrypted, plaintext, plaintext_len);

  butane_free(ctx);
}

static void test_encrypt_decrypt_single_byte(void) {
  butane_t ctx = create_ctx_with_derived_key();
  BT_ASSERT_NOT_NULL(ctx);

  const uint8_t plaintext[1] = {0x42};
  uint8_t ciphertext[1];
  uint8_t decrypted[1];
  uint8_t nonce[BUTANE_MAX_NONCE_SIZE];
  uint8_t tag[BUTANE_TAG_SIZE];

  int ret = butane_encrypt(ctx, plaintext, 1, ciphertext, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_OK);

  ret = butane_decrypt(ctx, ciphertext, 1, decrypted, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_OK);
  BT_ASSERT_EQ_MEM(decrypted, plaintext, 1);

  butane_free(ctx);
}

static void test_encrypt_decrypt_large_payload(void) {
  butane_t ctx = create_ctx_with_derived_key();
  BT_ASSERT_NOT_NULL(ctx);

  // 4096 bytes, crosses multiple cipher blocks
  size_t payload_size = 4096;
  uint8_t *plaintext = malloc(payload_size);
  uint8_t *ciphertext = malloc(payload_size);
  uint8_t *decrypted = malloc(payload_size);
  BT_ASSERT_NOT_NULL(plaintext);
  BT_ASSERT_NOT_NULL(ciphertext);
  BT_ASSERT_NOT_NULL(decrypted);

  for (size_t i = 0; i < payload_size; i++)
    plaintext[i] = (uint8_t)(i & 0xFF);

  uint8_t nonce[BUTANE_MAX_NONCE_SIZE];
  uint8_t tag[BUTANE_TAG_SIZE];

  int ret =
      butane_encrypt(ctx, plaintext, payload_size, ciphertext, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_OK);

  ret = butane_decrypt(ctx, ciphertext, payload_size, decrypted, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_OK);
  BT_ASSERT_EQ_MEM(decrypted, plaintext, payload_size);

  free(plaintext);
  free(ciphertext);
  free(decrypted);
  butane_free(ctx);
}

static void test_encrypt_decrypt_empty_payload(void) {
  butane_t ctx = create_ctx_with_derived_key();
  BT_ASSERT_NOT_NULL(ctx);

  uint8_t nonce[BUTANE_MAX_NONCE_SIZE];
  uint8_t tag[BUTANE_TAG_SIZE];

  int ret = butane_encrypt(ctx, NULL, 0, NULL, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_OK);

  ret = butane_decrypt(ctx, NULL, 0, NULL, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_OK);

  butane_free(ctx);
}

// === security path: tag tampering ===

static void test_tampered_tag_rejects(void) {
  butane_t ctx = create_ctx_with_derived_key();
  BT_ASSERT_NOT_NULL(ctx);

  const uint8_t plaintext[] = "sensitive data that must be authenticated";
  size_t plaintext_len = sizeof(plaintext) - 1;

  uint8_t ciphertext[128];
  uint8_t decrypted[128];
  uint8_t nonce[BUTANE_MAX_NONCE_SIZE];
  uint8_t tag[BUTANE_TAG_SIZE];

  int ret =
      butane_encrypt(ctx, plaintext, plaintext_len, ciphertext, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_OK);

  // flip one bit in tag
  tag[0] ^= 0x01;

  ret = butane_decrypt(ctx, ciphertext, plaintext_len, decrypted, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_ERR_AUTH);

  butane_free(ctx);
}

static void test_tampered_ciphertext_rejects(void) {
  butane_t ctx = create_ctx_with_derived_key();
  BT_ASSERT_NOT_NULL(ctx);

  const uint8_t plaintext[] = "another secret message for integrity check";
  size_t plaintext_len = sizeof(plaintext) - 1;

  uint8_t ciphertext[128];
  uint8_t decrypted[128];
  uint8_t nonce[BUTANE_MAX_NONCE_SIZE];
  uint8_t tag[BUTANE_TAG_SIZE];

  int ret =
      butane_encrypt(ctx, plaintext, plaintext_len, ciphertext, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_OK);

  // flip one bit in ciphertext
  ciphertext[0] ^= 0x01;

  ret = butane_decrypt(ctx, ciphertext, plaintext_len, decrypted, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_ERR_AUTH);

  butane_free(ctx);
}

static void test_tampered_nonce_rejects(void) {
  butane_t ctx = create_ctx_with_derived_key();
  BT_ASSERT_NOT_NULL(ctx);

  const uint8_t plaintext[] = "nonce integrity matters";
  size_t plaintext_len = sizeof(plaintext) - 1;

  uint8_t ciphertext[128];
  uint8_t decrypted[128];
  uint8_t nonce[BUTANE_MAX_NONCE_SIZE];
  uint8_t tag[BUTANE_TAG_SIZE];

  int ret =
      butane_encrypt(ctx, plaintext, plaintext_len, ciphertext, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_OK);

  // flip one bit in nonce
  nonce[0] ^= 0x01;

  ret = butane_decrypt(ctx, ciphertext, plaintext_len, decrypted, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_ERR_AUTH);

  butane_free(ctx);
}

// === parameter validation ===

static void test_encrypt_null_ctx_rejects(void) {
  uint8_t in[16] = {0};
  uint8_t out[16];
  uint8_t nonce[BUTANE_MAX_NONCE_SIZE];
  uint8_t tag[BUTANE_TAG_SIZE];

  int ret = butane_encrypt(NULL, in, 16, out, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_ERR_PARAM);
}

static void test_decrypt_null_ctx_rejects(void) {
  uint8_t in[16] = {0};
  uint8_t out[16];
  uint8_t nonce[BUTANE_MAX_NONCE_SIZE] = {0};
  uint8_t tag[BUTANE_TAG_SIZE] = {0};

  int ret = butane_decrypt(NULL, in, 16, out, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_ERR_PARAM);
}

static void test_encrypt_without_key_rejects(void) {
  butane_t ctx = butane_init();
  BT_ASSERT_NOT_NULL(ctx);

  uint8_t in[16] = {0};
  uint8_t out[16];
  uint8_t nonce[BUTANE_MAX_NONCE_SIZE];
  uint8_t tag[BUTANE_TAG_SIZE];

  // no key derived yet
  int ret = butane_encrypt(ctx, in, 16, out, nonce, tag);
  BT_ASSERT_EQ_INT(ret, BUTANE_ERR_PARAM);

  butane_free(ctx);
}

static void test_two_encryptions_produce_different_nonces(void) {
  butane_t ctx = create_ctx_with_derived_key();
  BT_ASSERT_NOT_NULL(ctx);

  const uint8_t plaintext[] = "same input both times";
  size_t plaintext_len = sizeof(plaintext) - 1;

  uint8_t ct1[64], ct2[64];
  uint8_t nonce1[BUTANE_MAX_NONCE_SIZE], nonce2[BUTANE_MAX_NONCE_SIZE];
  uint8_t tag1[BUTANE_TAG_SIZE], tag2[BUTANE_TAG_SIZE];

  int ret1 = butane_encrypt(ctx, plaintext, plaintext_len, ct1, nonce1, tag1);
  int ret2 = butane_encrypt(ctx, plaintext, plaintext_len, ct2, nonce2, tag2);
  BT_ASSERT_EQ_INT(ret1, BUTANE_OK);
  BT_ASSERT_EQ_INT(ret2, BUTANE_OK);

  // nonces should differ with overwhelming probability
  int nonces_differ = memcmp(nonce1, nonce2, BUTANE_MAX_NONCE_SIZE) != 0;
  BT_ASSERT(nonces_differ, "two encryptions should produce different nonces");

  butane_free(ctx);
}

// === suite runner ===

void run_aead_tests(void) {
  BT_SUITE_BEGIN("AEAD (Hybrid AES-GCM / XChaCha20-Poly1305)");

  BT_RUN_TEST(test_cipher_mode_is_set);
  BT_RUN_TEST(test_cipher_mode_null_ctx);
  BT_RUN_TEST(test_encrypt_decrypt_roundtrip);
  BT_RUN_TEST(test_encrypt_decrypt_single_byte);
  BT_RUN_TEST(test_encrypt_decrypt_large_payload);
  BT_RUN_TEST(test_encrypt_decrypt_empty_payload);
  BT_RUN_TEST(test_tampered_tag_rejects);
  BT_RUN_TEST(test_tampered_ciphertext_rejects);
  BT_RUN_TEST(test_tampered_nonce_rejects);
  BT_RUN_TEST(test_encrypt_null_ctx_rejects);
  BT_RUN_TEST(test_decrypt_null_ctx_rejects);
  BT_RUN_TEST(test_encrypt_without_key_rejects);
  BT_RUN_TEST(test_two_encryptions_produce_different_nonces);
}
