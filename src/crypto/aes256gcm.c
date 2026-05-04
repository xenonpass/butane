#include "aes256gcm.h"
#include "butane.h"
#include <emmintrin.h>
#include <smmintrin.h>
#include <string.h>
#include <wmmintrin.h>

// === aes-256 key expansion with aes-ni ===

#define AES256_ROUNDS 14
#define AES256_ROUND_KEYS 15

static inline __m128i aes256_key_expand_assist(__m128i key, __m128i keygened) {
  keygened = _mm_shuffle_epi32(keygened, 0xFF);
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  return _mm_xor_si128(key, keygened);
}

static inline __m128i aes256_key_expand_assist2(__m128i key1, __m128i key2) {
  __m128i keygened = _mm_aeskeygenassist_si128(key1, 0x00);
  keygened = _mm_shuffle_epi32(keygened, 0xAA);
  key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
  key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
  key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
  return _mm_xor_si128(key2, keygened);
}

static void aes256_expand_key(const uint8_t *key,
                              __m128i round_keys[AES256_ROUND_KEYS]) {
  round_keys[0] = _mm_loadu_si128((const __m128i *)(key));
  round_keys[1] = _mm_loadu_si128((const __m128i *)(key + 16));
  round_keys[2] = aes256_key_expand_assist(
      round_keys[0], _mm_aeskeygenassist_si128(round_keys[1], 0x01));
  round_keys[3] = aes256_key_expand_assist2(round_keys[2], round_keys[1]);
  round_keys[4] = aes256_key_expand_assist(
      round_keys[2], _mm_aeskeygenassist_si128(round_keys[3], 0x02));
  round_keys[5] = aes256_key_expand_assist2(round_keys[4], round_keys[3]);
  round_keys[6] = aes256_key_expand_assist(
      round_keys[4], _mm_aeskeygenassist_si128(round_keys[5], 0x04));
  round_keys[7] = aes256_key_expand_assist2(round_keys[6], round_keys[5]);
  round_keys[8] = aes256_key_expand_assist(
      round_keys[6], _mm_aeskeygenassist_si128(round_keys[7], 0x08));
  round_keys[9] = aes256_key_expand_assist2(round_keys[8], round_keys[7]);
  round_keys[10] = aes256_key_expand_assist(
      round_keys[8], _mm_aeskeygenassist_si128(round_keys[9], 0x10));
  round_keys[11] = aes256_key_expand_assist2(round_keys[10], round_keys[9]);
  round_keys[12] = aes256_key_expand_assist(
      round_keys[10], _mm_aeskeygenassist_si128(round_keys[11], 0x20));
  round_keys[13] = aes256_key_expand_assist2(round_keys[12], round_keys[11]);
  round_keys[14] = aes256_key_expand_assist(
      round_keys[12], _mm_aeskeygenassist_si128(round_keys[13], 0x40));
}

// encrypt single aes-256 block
static inline __m128i
aes256_encrypt_block(__m128i block,
                     const __m128i round_keys[AES256_ROUND_KEYS]) {
  block = _mm_xor_si128(block, round_keys[0]);
  for (int i = 1; i < AES256_ROUNDS; i++)
    block = _mm_aesenc_si128(block, round_keys[i]);
  return _mm_aesenclast_si128(block, round_keys[AES256_ROUNDS]);
}

// === gcm ghash ===

// increment the rightmost 32 bits of a 128-bit counter (big-endian)
static inline __m128i gcm_increment_counter(__m128i counter) {
  uint8_t ctr_bytes[16];
  _mm_storeu_si128((__m128i *)ctr_bytes, counter);

  // counter is in last 4 bytes (big-endian)
  uint32_t cval = ((uint32_t)ctr_bytes[12] << 24) |
                  ((uint32_t)ctr_bytes[13] << 16) |
                  ((uint32_t)ctr_bytes[14] << 8) | ((uint32_t)ctr_bytes[15]);
  cval++;
  ctr_bytes[12] = (uint8_t)(cval >> 24);
  ctr_bytes[13] = (uint8_t)(cval >> 16);
  ctr_bytes[14] = (uint8_t)(cval >> 8);
  ctr_bytes[15] = (uint8_t)(cval);

  return _mm_loadu_si128((const __m128i *)ctr_bytes);
}

// gf(2^128) multiplication using pclmulqdq
static __m128i ghash_multiply(__m128i a, __m128i b) {
  __m128i tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6;

  tmp0 = _mm_clmulepi64_si128(a, b, 0x00);
  tmp1 = _mm_clmulepi64_si128(a, b, 0x01);
  tmp2 = _mm_clmulepi64_si128(a, b, 0x10);
  tmp3 = _mm_clmulepi64_si128(a, b, 0x11);

  tmp1 = _mm_xor_si128(tmp1, tmp2);
  tmp2 = _mm_slli_si128(tmp1, 8);
  tmp1 = _mm_srli_si128(tmp1, 8);

  tmp0 = _mm_xor_si128(tmp0, tmp2);
  tmp3 = _mm_xor_si128(tmp3, tmp1);

  // reduce mod x^128 + x^7 + x^2 + x + 1
  tmp4 = _mm_srli_epi32(tmp0, 31);
  tmp5 = _mm_srli_epi32(tmp0, 30);
  tmp6 = _mm_srli_epi32(tmp0, 25);

  tmp4 = _mm_xor_si128(tmp4, tmp5);
  tmp4 = _mm_xor_si128(tmp4, tmp6);

  tmp5 = _mm_srli_si128(tmp4, 4);
  tmp4 = _mm_slli_si128(tmp4, 12);
  tmp0 = _mm_xor_si128(tmp0, tmp4);

  tmp4 = _mm_slli_epi32(tmp0, 1);
  tmp5 = _mm_xor_si128(tmp5, tmp4);
  tmp4 = _mm_slli_epi32(tmp0, 2);
  tmp5 = _mm_xor_si128(tmp5, tmp4);
  tmp4 = _mm_slli_epi32(tmp0, 7);
  tmp5 = _mm_xor_si128(tmp5, tmp4);

  tmp0 = _mm_xor_si128(tmp0, tmp5);
  tmp3 = _mm_xor_si128(tmp3, tmp0);

  return tmp3;
}

// reverse byte order for ghash (gcm uses big-endian representation)
static inline __m128i byte_reverse(__m128i x) {
  __m128i mask =
      _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
  return _mm_shuffle_epi8(x, mask);
}

// === aes-256-gcm aead ===

int aes256gcm_encrypt(const uint8_t *key, const uint8_t *iv12,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint8_t *ciphertext, uint8_t *tag16) {
  if (!key || !iv12 || !tag16)
    return BUTANE_ERR_PARAM;
  if (plaintext_len > 0 && (!plaintext || !ciphertext))
    return BUTANE_ERR_PARAM;

  __m128i round_keys[AES256_ROUND_KEYS];
  aes256_expand_key(key, round_keys);

  // derive hash subkey H = AES(K, 0^128)
  __m128i hash_subkey = aes256_encrypt_block(_mm_setzero_si128(), round_keys);
  hash_subkey = byte_reverse(hash_subkey);

  // build initial counter J0 = IV || 0x00000001
  uint8_t j0_bytes[16];
  memcpy(j0_bytes, iv12, 12);
  j0_bytes[12] = 0x00;
  j0_bytes[13] = 0x00;
  j0_bytes[14] = 0x00;
  j0_bytes[15] = 0x01;
  __m128i j0 = _mm_loadu_si128((const __m128i *)j0_bytes);

  // encrypt J0 for final tag xor
  __m128i encrypted_j0 = aes256_encrypt_block(j0, round_keys);

  // encrypt plaintext with counter starting at J0+1
  __m128i counter = gcm_increment_counter(j0);
  size_t full_blocks = plaintext_len / 16;
  size_t remaining_bytes = plaintext_len % 16;

  // ghash accumulator
  __m128i ghash_acc = _mm_setzero_si128();

  for (size_t i = 0; i < full_blocks; i++) {
    __m128i keystream = aes256_encrypt_block(counter, round_keys);
    __m128i pt_block = _mm_loadu_si128((const __m128i *)(plaintext + i * 16));
    __m128i ct_block = _mm_xor_si128(pt_block, keystream);
    _mm_storeu_si128((__m128i *)(ciphertext + i * 16), ct_block);

    // ghash: accumulate ciphertext
    ghash_acc = _mm_xor_si128(ghash_acc, byte_reverse(ct_block));
    ghash_acc = ghash_multiply(ghash_acc, hash_subkey);

    counter = gcm_increment_counter(counter);
  }

  // handle partial last block
  if (remaining_bytes > 0) {
    __m128i keystream = aes256_encrypt_block(counter, round_keys);
    uint8_t ks_bytes[16];
    _mm_storeu_si128((__m128i *)ks_bytes, keystream);

    uint8_t last_ct[16];
    memset(last_ct, 0, 16);
    for (size_t i = 0; i < remaining_bytes; i++) {
      ciphertext[full_blocks * 16 + i] =
          plaintext[full_blocks * 16 + i] ^ ks_bytes[i];
      last_ct[i] = ciphertext[full_blocks * 16 + i];
    }

    __m128i ct_block = _mm_loadu_si128((const __m128i *)last_ct);
    ghash_acc = _mm_xor_si128(ghash_acc, byte_reverse(ct_block));
    ghash_acc = ghash_multiply(ghash_acc, hash_subkey);

    butane_clean(ks_bytes, sizeof(ks_bytes));
    butane_clean(last_ct, sizeof(last_ct));
  }

  // ghash finalize: add length block (no aad, so aad_len = 0)
  uint8_t len_block[16];
  memset(len_block, 0, 16);
  // big-endian bit lengths
  uint64_t ct_bits = (uint64_t)plaintext_len * 8;
  len_block[4] = (uint8_t)(0); // aad bits = 0
  len_block[5] = (uint8_t)(0);
  len_block[6] = (uint8_t)(0);
  len_block[7] = (uint8_t)(0);
  len_block[8] = (uint8_t)(ct_bits >> 56);
  len_block[9] = (uint8_t)(ct_bits >> 48);
  len_block[10] = (uint8_t)(ct_bits >> 40);
  len_block[11] = (uint8_t)(ct_bits >> 32);
  len_block[12] = (uint8_t)(ct_bits >> 24);
  len_block[13] = (uint8_t)(ct_bits >> 16);
  len_block[14] = (uint8_t)(ct_bits >> 8);
  len_block[15] = (uint8_t)(ct_bits);

  __m128i len_vec = _mm_loadu_si128((const __m128i *)len_block);
  ghash_acc = _mm_xor_si128(ghash_acc, byte_reverse(len_vec));
  ghash_acc = ghash_multiply(ghash_acc, hash_subkey);

  // final tag = GHASH ^ E(K, J0)
  __m128i tag_vec = _mm_xor_si128(byte_reverse(ghash_acc), encrypted_j0);
  _mm_storeu_si128((__m128i *)tag16, tag_vec);

  // wipe round keys
  butane_clean(round_keys, sizeof(round_keys));
  butane_clean(j0_bytes, sizeof(j0_bytes));
  butane_clean(len_block, sizeof(len_block));

  return BUTANE_OK;
}

int aes256gcm_decrypt(const uint8_t *key, const uint8_t *iv12,
                      const uint8_t *ciphertext, size_t ciphertext_len,
                      uint8_t *plaintext, const uint8_t *tag16) {
  if (!key || !iv12 || !tag16)
    return BUTANE_ERR_PARAM;
  if (ciphertext_len > 0 && (!ciphertext || !plaintext))
    return BUTANE_ERR_PARAM;

  __m128i round_keys[AES256_ROUND_KEYS];
  aes256_expand_key(key, round_keys);

  __m128i hash_subkey = aes256_encrypt_block(_mm_setzero_si128(), round_keys);
  hash_subkey = byte_reverse(hash_subkey);

  uint8_t j0_bytes[16];
  memcpy(j0_bytes, iv12, 12);
  j0_bytes[12] = 0x00;
  j0_bytes[13] = 0x00;
  j0_bytes[14] = 0x00;
  j0_bytes[15] = 0x01;
  __m128i j0 = _mm_loadu_si128((const __m128i *)j0_bytes);
  __m128i encrypted_j0 = aes256_encrypt_block(j0, round_keys);

  // recompute ghash over ciphertext to verify tag
  __m128i ghash_acc = _mm_setzero_si128();
  size_t full_blocks = ciphertext_len / 16;
  size_t remaining_bytes = ciphertext_len % 16;

  for (size_t i = 0; i < full_blocks; i++) {
    __m128i ct_block = _mm_loadu_si128((const __m128i *)(ciphertext + i * 16));
    ghash_acc = _mm_xor_si128(ghash_acc, byte_reverse(ct_block));
    ghash_acc = ghash_multiply(ghash_acc, hash_subkey);
  }

  if (remaining_bytes > 0) {
    uint8_t last_ct[16];
    memset(last_ct, 0, 16);
    memcpy(last_ct, ciphertext + full_blocks * 16, remaining_bytes);
    __m128i ct_block = _mm_loadu_si128((const __m128i *)last_ct);
    ghash_acc = _mm_xor_si128(ghash_acc, byte_reverse(ct_block));
    ghash_acc = ghash_multiply(ghash_acc, hash_subkey);
    butane_clean(last_ct, sizeof(last_ct));
  }

  uint8_t len_block[16];
  memset(len_block, 0, 16);
  uint64_t ct_bits = (uint64_t)ciphertext_len * 8;
  len_block[8] = (uint8_t)(ct_bits >> 56);
  len_block[9] = (uint8_t)(ct_bits >> 48);
  len_block[10] = (uint8_t)(ct_bits >> 40);
  len_block[11] = (uint8_t)(ct_bits >> 32);
  len_block[12] = (uint8_t)(ct_bits >> 24);
  len_block[13] = (uint8_t)(ct_bits >> 16);
  len_block[14] = (uint8_t)(ct_bits >> 8);
  len_block[15] = (uint8_t)(ct_bits);

  __m128i len_vec = _mm_loadu_si128((const __m128i *)len_block);
  ghash_acc = _mm_xor_si128(ghash_acc, byte_reverse(len_vec));
  ghash_acc = ghash_multiply(ghash_acc, hash_subkey);

  __m128i computed_tag_vec =
      _mm_xor_si128(byte_reverse(ghash_acc), encrypted_j0);
  uint8_t computed_tag[16];
  _mm_storeu_si128((__m128i *)computed_tag, computed_tag_vec);

  // constant-time tag verification
  uint8_t diff = 0;
  for (int i = 0; i < 16; i++)
    diff |= computed_tag[i] ^ tag16[i];

  butane_clean(computed_tag, sizeof(computed_tag));

  if (diff != 0) {
    butane_clean(round_keys, sizeof(round_keys));
    butane_clean(j0_bytes, sizeof(j0_bytes));
    butane_clean(len_block, sizeof(len_block));
    return BUTANE_ERR_AUTH;
  }

  // decrypt ciphertext
  __m128i counter = gcm_increment_counter(j0);

  for (size_t i = 0; i < full_blocks; i++) {
    __m128i keystream = aes256_encrypt_block(counter, round_keys);
    __m128i ct_block = _mm_loadu_si128((const __m128i *)(ciphertext + i * 16));
    __m128i pt_block = _mm_xor_si128(ct_block, keystream);
    _mm_storeu_si128((__m128i *)(plaintext + i * 16), pt_block);
    counter = gcm_increment_counter(counter);
  }

  if (remaining_bytes > 0) {
    __m128i keystream = aes256_encrypt_block(counter, round_keys);
    uint8_t ks_bytes[16];
    _mm_storeu_si128((__m128i *)ks_bytes, keystream);
    for (size_t i = 0; i < remaining_bytes; i++)
      plaintext[full_blocks * 16 + i] =
          ciphertext[full_blocks * 16 + i] ^ ks_bytes[i];
    butane_clean(ks_bytes, sizeof(ks_bytes));
  }

  butane_clean(round_keys, sizeof(round_keys));
  butane_clean(j0_bytes, sizeof(j0_bytes));
  butane_clean(len_block, sizeof(len_block));

  return BUTANE_OK;
}
