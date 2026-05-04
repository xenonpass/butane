#include "chacha20.h"
#include "butane.h"
#include <stdlib.h>
#include <string.h>

// === quarter round and core ===

static inline uint32_t load32_le(const uint8_t *p) {
  return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static inline uint64_t load64_le(const uint8_t *p) {
  return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
         ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
         ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
         ((uint64_t)p[7] << 56);
}

static inline void store64_le(uint8_t *p, uint64_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
  p[4] = (uint8_t)(v >> 32);
  p[5] = (uint8_t)(v >> 40);
  p[6] = (uint8_t)(v >> 48);
  p[7] = (uint8_t)(v >> 56);
}

static inline uint32_t rotl32(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

#define QUARTERROUND(a, b, c, d)                                               \
  do {                                                                         \
    a += b;                                                                    \
    d ^= a;                                                                    \
    d = rotl32(d, 16);                                                         \
    c += d;                                                                    \
    b ^= c;                                                                    \
    b = rotl32(b, 12);                                                         \
    a += b;                                                                    \
    d ^= a;                                                                    \
    d = rotl32(d, 8);                                                          \
    c += d;                                                                    \
    b ^= c;                                                                    \
    b = rotl32(b, 7);                                                          \
  } while (0)

// chacha20 block function: 20 rounds on 16-word state
static void chacha20_block(uint32_t output[16], const uint32_t input[16]) {
  uint32_t x[16];
  memcpy(x, input, 64);

  for (int i = 0; i < 10; i++) {
    // column rounds
    QUARTERROUND(x[0], x[4], x[8], x[12]);
    QUARTERROUND(x[1], x[5], x[9], x[13]);
    QUARTERROUND(x[2], x[6], x[10], x[14]);
    QUARTERROUND(x[3], x[7], x[11], x[15]);
    // diagonal rounds
    QUARTERROUND(x[0], x[5], x[10], x[15]);
    QUARTERROUND(x[1], x[6], x[11], x[12]);
    QUARTERROUND(x[2], x[7], x[8], x[13]);
    QUARTERROUND(x[3], x[4], x[9], x[14]);
  }

  for (int i = 0; i < 16; i++)
    output[i] = x[i] + input[i];
}

// === chacha20 keystream xor ===

void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                  const uint8_t *key, const uint8_t *nonce,
                  uint32_t initial_counter) {
  uint32_t state[16];

  // "expand 32-byte k"
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;

  for (int i = 0; i < 8; i++)
    state[4 + i] = load32_le(key + 4 * i);

  state[12] = initial_counter;
  state[13] = load32_le(nonce + 0);
  state[14] = load32_le(nonce + 4);
  state[15] = load32_le(nonce + 8);

  uint32_t keystream_block[16];
  size_t offset = 0;

  while (offset < len) {
    chacha20_block(keystream_block, state);
    state[12]++;

    uint8_t keystream_bytes[64];
    for (int i = 0; i < 16; i++)
      store32_le(keystream_bytes + 4 * i, keystream_block[i]);

    size_t block_remaining = len - offset;
    if (block_remaining > 64)
      block_remaining = 64;

    for (size_t i = 0; i < block_remaining; i++)
      out[offset + i] = in[offset + i] ^ keystream_bytes[i];

    offset += block_remaining;
    butane_clean(keystream_bytes, sizeof(keystream_bytes));
  }

  butane_clean(keystream_block, sizeof(keystream_block));
  butane_clean(state, sizeof(state));
}

// === hchacha20 for xchacha20 subkey derivation ===

void hchacha20(uint8_t *subkey, const uint8_t *key, const uint8_t *nonce16) {
  uint32_t x[16];

  x[0] = 0x61707865;
  x[1] = 0x3320646e;
  x[2] = 0x79622d32;
  x[3] = 0x6b206574;

  for (int i = 0; i < 8; i++)
    x[4 + i] = load32_le(key + 4 * i);

  // hchacha20 uses first 16 bytes of nonce as input words 12-15
  for (int i = 0; i < 4; i++)
    x[12 + i] = load32_le(nonce16 + 4 * i);

  for (int i = 0; i < 10; i++) {
    QUARTERROUND(x[0], x[4], x[8], x[12]);
    QUARTERROUND(x[1], x[5], x[9], x[13]);
    QUARTERROUND(x[2], x[6], x[10], x[14]);
    QUARTERROUND(x[3], x[7], x[11], x[15]);
    QUARTERROUND(x[0], x[5], x[10], x[15]);
    QUARTERROUND(x[1], x[6], x[11], x[12]);
    QUARTERROUND(x[2], x[7], x[8], x[13]);
    QUARTERROUND(x[3], x[4], x[9], x[14]);
  }

  // output words 0-3 and 12-15 (no addition step)
  store32_le(subkey + 0, x[0]);
  store32_le(subkey + 4, x[1]);
  store32_le(subkey + 8, x[2]);
  store32_le(subkey + 12, x[3]);
  store32_le(subkey + 16, x[12]);
  store32_le(subkey + 20, x[13]);
  store32_le(subkey + 24, x[14]);
  store32_le(subkey + 28, x[15]);

  butane_clean(x, sizeof(x));
}

// === poly1305 ===

// poly1305 using 130-bit arithmetic with 64-bit limbs
void poly1305_auth(uint8_t *tag, const uint8_t *msg, size_t msg_len,
                   const uint8_t *key32) {
  // clamp r
  uint64_t t0 = load64_le(key32 + 0);
  uint64_t t1 = load64_le(key32 + 8);

  uint64_t r0 = t0 & 0x0FFFFFFC0FFFFFFFULL;
  uint64_t r1 = t1 & 0x0FFFFFFC0FFFFFFCULL;

  // r in 44/42/44 radix
  uint64_t rr0 = r0 & ((1ULL << 44) - 1);
  uint64_t rr1 = ((r0 >> 44) | (r1 << 20)) & ((1ULL << 44) - 1);
  uint64_t rr2 = (r1 >> 24) & ((1ULL << 42) - 1);

  // precompute 5*r for reduction
  uint64_t s1 = rr1 * 5;
  uint64_t s2 = rr2 * 5;

  uint64_t h0 = 0, h1 = 0, h2 = 0;

  size_t offset = 0;
  while (offset < msg_len) {
    size_t block_size = msg_len - offset;
    if (block_size > 16)
      block_size = 16;

    // load message block and add high bit
    uint8_t block[17];
    memset(block, 0, sizeof(block));
    memcpy(block, msg + offset, block_size);
    block[block_size] = 1;

    uint64_t m0 = load64_le(block + 0);
    uint64_t m1 = load64_le(block + 8);
    uint64_t hibit = (block_size < 16) ? 0 : ((uint64_t)block[16]);

    // add message to accumulator in 44/44/42 radix
    h0 += m0 & ((1ULL << 44) - 1);
    h1 += ((m0 >> 44) | (m1 << 20)) & ((1ULL << 44) - 1);
    h2 += ((m1 >> 24)) | (hibit << 40);

    // multiply and reduce
    __uint128_t d0 =
        (__uint128_t)h0 * rr0 + (__uint128_t)h1 * s2 + (__uint128_t)h2 * s1;
    __uint128_t d1 =
        (__uint128_t)h0 * rr1 + (__uint128_t)h1 * rr0 + (__uint128_t)h2 * s2;
    __uint128_t d2 =
        (__uint128_t)h0 * rr2 + (__uint128_t)h1 * rr1 + (__uint128_t)h2 * rr0;

    // partial reduction mod 2^130-5
    uint64_t c;
    h0 = (uint64_t)d0 & ((1ULL << 44) - 1);
    c = (uint64_t)(d0 >> 44);
    d1 += c;
    h1 = (uint64_t)d1 & ((1ULL << 44) - 1);
    c = (uint64_t)(d1 >> 44);
    d2 += c;
    h2 = (uint64_t)d2 & ((1ULL << 42) - 1);
    c = (uint64_t)(d2 >> 42);
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= (1ULL << 44) - 1;
    h1 += c;

    offset += block_size;
  }

  // full carry and final reduction
  uint64_t c = h1 >> 44;
  h1 &= (1ULL << 44) - 1;
  h2 += c;
  c = h2 >> 42;
  h2 &= (1ULL << 42) - 1;
  h0 += c * 5;
  c = h0 >> 44;
  h0 &= (1ULL << 44) - 1;
  h1 += c;

  // compute h + -(2^130-5) to check if h >= 2^130-5
  uint64_t g0 = h0 + 5;
  c = g0 >> 44;
  g0 &= (1ULL << 44) - 1;
  uint64_t g1 = h1 + c;
  c = g1 >> 44;
  g1 &= (1ULL << 44) - 1;
  uint64_t g2 = h2 + c - (1ULL << 42);

  // select h or g based on whether g overflowed
  uint64_t mask = (g2 >> 63) - 1;
  h0 = (h0 & ~mask) | (g0 & mask);
  h1 = (h1 & ~mask) | (g1 & mask);
  h2 = (h2 & ~mask) | (g2 & mask);

  // convert back to two 64-bit words
  uint64_t f0 = h0 | (h1 << 44);
  uint64_t f1 = (h1 >> 20) | (h2 << 24);

  // add pad (s part of key)
  uint64_t pad0 = load64_le(key32 + 16);
  uint64_t pad1 = load64_le(key32 + 24);

  __uint128_t sum = (__uint128_t)f0 + pad0;
  f0 = (uint64_t)sum;
  sum = (__uint128_t)f1 + pad1 + (uint64_t)(sum >> 64);
  f1 = (uint64_t)sum;

  store64_le(tag + 0, f0);
  store64_le(tag + 8, f1);
}

// === xchacha20-poly1305 aead ===

// construct poly1305 key from first 32 bytes of chacha20 keystream (counter=0)
static void derive_poly1305_key(uint8_t *poly_key, const uint8_t *key,
                                const uint8_t *nonce) {
  uint8_t zeros[32];
  memset(zeros, 0, sizeof(zeros));
  chacha20_xor(poly_key, zeros, 32, key, nonce, 0);
  butane_clean(zeros, sizeof(zeros));
}

// pad length to 16-byte boundary
static void poly1305_pad16(uint8_t *mac_data, size_t *mac_data_len,
                           size_t data_len) {
  size_t remainder = data_len % 16;
  if (remainder != 0) {
    size_t pad_len = 16 - remainder;
    memset(mac_data + *mac_data_len, 0, pad_len);
    *mac_data_len += pad_len;
  }
}

int xchacha20poly1305_encrypt(const uint8_t *key, const uint8_t *nonce24,
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext, uint8_t *tag16) {
  if (!key || !nonce24 || !tag16)
    return BUTANE_ERR_PARAM;
  if (plaintext_len > 0 && (!plaintext || !ciphertext))
    return BUTANE_ERR_PARAM;

  // derive xchacha20 subkey from first 16 nonce bytes
  uint8_t subkey[32];
  hchacha20(subkey, key, nonce24);

  // construct inner nonce: 4 zero bytes + last 8 bytes of nonce24
  uint8_t inner_nonce[12];
  memset(inner_nonce, 0, 4);
  memcpy(inner_nonce + 4, nonce24 + 16, 8);

  // derive poly1305 otk from counter=0 block
  uint8_t poly_key[32];
  derive_poly1305_key(poly_key, subkey, inner_nonce);

  // encrypt plaintext with counter starting at 1
  if (plaintext_len > 0)
    chacha20_xor(ciphertext, plaintext, plaintext_len, subkey, inner_nonce, 1);

  // build poly1305 input: no aad, pad, ciphertext, pad, lengths
  // format: ciphertext || pad || le64(0) || le64(ciphertext_len)
  size_t mac_data_capacity = plaintext_len + 16 + 16;
  uint8_t *mac_data = malloc(mac_data_capacity);
  if (!mac_data) {
    butane_clean(subkey, sizeof(subkey));
    butane_clean(inner_nonce, sizeof(inner_nonce));
    butane_clean(poly_key, sizeof(poly_key));
    return BUTANE_ERR_NOMEM;
  }

  size_t mac_data_len = 0;

  // no aad — still need empty pad (already zero length, skip)
  // ciphertext
  if (plaintext_len > 0) {
    memcpy(mac_data + mac_data_len, ciphertext, plaintext_len);
    mac_data_len += plaintext_len;
  }
  poly1305_pad16(mac_data, &mac_data_len, plaintext_len);

  // le64(aad_len=0) || le64(ciphertext_len)
  store64_le(mac_data + mac_data_len, 0);
  mac_data_len += 8;
  store64_le(mac_data + mac_data_len, (uint64_t)plaintext_len);
  mac_data_len += 8;

  poly1305_auth(tag16, mac_data, mac_data_len, poly_key);

  butane_clean(mac_data, mac_data_len);
  free(mac_data);
  butane_clean(subkey, sizeof(subkey));
  butane_clean(inner_nonce, sizeof(inner_nonce));
  butane_clean(poly_key, sizeof(poly_key));

  return BUTANE_OK;
}

int xchacha20poly1305_decrypt(const uint8_t *key, const uint8_t *nonce24,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext, const uint8_t *tag16) {
  if (!key || !nonce24 || !tag16)
    return BUTANE_ERR_PARAM;
  if (ciphertext_len > 0 && (!ciphertext || !plaintext))
    return BUTANE_ERR_PARAM;

  uint8_t subkey[32];
  hchacha20(subkey, key, nonce24);

  uint8_t inner_nonce[12];
  memset(inner_nonce, 0, 4);
  memcpy(inner_nonce + 4, nonce24 + 16, 8);

  uint8_t poly_key[32];
  derive_poly1305_key(poly_key, subkey, inner_nonce);

  // recompute tag from ciphertext
  size_t mac_data_capacity = ciphertext_len + 16 + 16;
  uint8_t *mac_data = malloc(mac_data_capacity);
  if (!mac_data) {
    butane_clean(subkey, sizeof(subkey));
    butane_clean(inner_nonce, sizeof(inner_nonce));
    butane_clean(poly_key, sizeof(poly_key));
    return BUTANE_ERR_NOMEM;
  }

  size_t mac_data_len = 0;

  if (ciphertext_len > 0) {
    memcpy(mac_data + mac_data_len, ciphertext, ciphertext_len);
    mac_data_len += ciphertext_len;
  }
  poly1305_pad16(mac_data, &mac_data_len, ciphertext_len);

  store64_le(mac_data + mac_data_len, 0);
  mac_data_len += 8;
  store64_le(mac_data + mac_data_len, (uint64_t)ciphertext_len);
  mac_data_len += 8;

  uint8_t computed_tag[16];
  poly1305_auth(computed_tag, mac_data, mac_data_len, poly_key);

  butane_clean(mac_data, mac_data_len);
  free(mac_data);

  // constant-time tag comparison
  uint8_t diff = 0;
  for (int i = 0; i < 16; i++)
    diff |= computed_tag[i] ^ tag16[i];

  butane_clean(computed_tag, sizeof(computed_tag));

  if (diff != 0) {
    butane_clean(subkey, sizeof(subkey));
    butane_clean(inner_nonce, sizeof(inner_nonce));
    butane_clean(poly_key, sizeof(poly_key));
    return BUTANE_ERR_AUTH;
  }

  // decrypt ciphertext with counter starting at 1
  if (ciphertext_len > 0)
    chacha20_xor(plaintext, ciphertext, ciphertext_len, subkey, inner_nonce, 1);

  butane_clean(subkey, sizeof(subkey));
  butane_clean(inner_nonce, sizeof(inner_nonce));
  butane_clean(poly_key, sizeof(poly_key));

  return BUTANE_OK;
}
