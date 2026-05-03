#include "blake2b.h"
#include "butane.h"
#include <string.h>

static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
};

static inline uint64_t rotr64(uint64_t x, unsigned int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t load64_le(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint64_t)p[0])       | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void store32_le(void *dst, uint32_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(w);
    p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
}

static inline void store64_le(void *dst, uint64_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(w);
    p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
    p[4] = (uint8_t)(w >> 32);
    p[5] = (uint8_t)(w >> 40);
    p[6] = (uint8_t)(w >> 48);
    p[7] = (uint8_t)(w >> 56);
}

#define G(r, i, a, b, c, d) do {                         \
    a = a + b + load64_le(&block[8 * sigma[r][2*i]]);    \
    d = rotr64(d ^ a, 32);                               \
    c = c + d;                                           \
    b = rotr64(b ^ c, 24);                               \
    a = a + b + load64_le(&block[8 * sigma[r][2*i+1]]);  \
    d = rotr64(d ^ a, 16);                               \
    c = c + d;                                           \
    b = rotr64(b ^ c, 63);                               \
} while(0)

#define ROUND(r) do {       \
    G(r, 0, v[0], v[4], v[ 8], v[12]); \
    G(r, 1, v[1], v[5], v[ 9], v[13]); \
    G(r, 2, v[2], v[6], v[10], v[14]); \
    G(r, 3, v[3], v[7], v[11], v[15]); \
    G(r, 4, v[0], v[5], v[10], v[15]); \
    G(r, 5, v[1], v[6], v[11], v[12]); \
    G(r, 6, v[2], v[7], v[ 8], v[13]); \
    G(r, 7, v[3], v[4], v[ 9], v[14]); \
} while(0)

// blake2b_compress (compresses 128byte block)
static void blake2b_compress(blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES]) {
    const uint8_t (*sigma)[16] = blake2b_sigma;
    uint64_t v[16];

    v[ 0] = S->h[0]; v[ 1] = S->h[1]; v[ 2] = S->h[2]; v[ 3] = S->h[3];
    v[ 4] = S->h[4]; v[ 5] = S->h[5]; v[ 6] = S->h[6]; v[ 7] = S->h[7];
    v[ 8] = blake2b_IV[0]; v[ 9] = blake2b_IV[1];
    v[10] = blake2b_IV[2]; v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ S->t[0];
    v[13] = blake2b_IV[5] ^ S->t[1];
    v[14] = blake2b_IV[6] ^ S->f[0];
    v[15] = blake2b_IV[7] ^ S->f[1];

    ROUND(0);  ROUND(1);  ROUND(2);  ROUND(3);
    ROUND(4);  ROUND(5);  ROUND(6);  ROUND(7);
    ROUND(8);  ROUND(9);  ROUND(10); ROUND(11);

    for (int i = 0; i < 8; i++)
        S->h[i] ^= v[i] ^ v[i + 8];
}

// init blake2b (nokey)
int blake2b_init(blake2b_state *S, size_t outlen) {
    if (!S || outlen == 0 || outlen > BLAKE2B_OUTBYTES)
        return -1;

    memset(S, 0, sizeof(blake2b_state));
    for (int i = 0; i < 8; i++)
        S->h[i] = blake2b_IV[i];

    S->h[0] ^= 0x01010000 ^ (uint64_t)outlen;
    S->outlen = outlen;
    return 0;
}

/* setup blake2b with a secret key */
int blake2b_init_key(blake2b_state *S, size_t outlen,
                     const void *key, size_t keylen) {
    if (!S || outlen == 0 || outlen > BLAKE2B_OUTBYTES)
        return -1;
    if (!key || keylen == 0 || keylen > BLAKE2B_KEYBYTES)
        return -1;

    memset(S, 0, sizeof(blake2b_state));
    for (int i = 0; i < 8; i++)
        S->h[i] = blake2b_IV[i];

    S->h[0] ^= 0x01010000 ^ ((uint64_t)keylen << 8) ^ (uint64_t)outlen;
    S->outlen = outlen;

    uint8_t block[BLAKE2B_BLOCKBYTES];
    memset(block, 0, BLAKE2B_BLOCKBYTES);
    memcpy(block, key, keylen);
    blake2b_update(S, block, BLAKE2B_BLOCKBYTES);
    butane_clean(block, BLAKE2B_BLOCKBYTES);
    return 0;
}

// *ingest random length input
int blake2b_update(blake2b_state *S, const void *in, size_t inlen) {
    if (!S)
        return -1;
    if (inlen == 0)
        return 0;

    const uint8_t *pin = (const uint8_t *)in;

    if (S->buflen + inlen > BLAKE2B_BLOCKBYTES) {
        size_t left = S->buflen;
        size_t fill = BLAKE2B_BLOCKBYTES - left;

        if (fill <= inlen) {
            memcpy(S->buf + left, pin, fill);
            S->t[0] += BLAKE2B_BLOCKBYTES;
            if (S->t[0] < BLAKE2B_BLOCKBYTES)
                S->t[1]++;
            blake2b_compress(S, S->buf);
            S->buflen = 0;
            pin += fill;
            inlen -= fill;
        }

        while (inlen > BLAKE2B_BLOCKBYTES) {
            S->t[0] += BLAKE2B_BLOCKBYTES;
            if (S->t[0] < BLAKE2B_BLOCKBYTES)
                S->t[1]++;
            blake2b_compress(S, pin);
            pin += BLAKE2B_BLOCKBYTES;
            inlen -= BLAKE2B_BLOCKBYTES;
        }
    }

    if (inlen > 0) {
        memcpy(S->buf + S->buflen, pin, inlen);
        S->buflen += inlen;
    }

    return 0;
}

// final hash
int blake2b_final(blake2b_state *S, void *out, size_t outlen) {
    if (!S || !out || outlen < S->outlen)
        return -1;

    S->t[0] += (uint64_t)S->buflen;
    if (S->t[0] < (uint64_t)S->buflen)
        S->t[1]++;

    S->f[0] = (uint64_t)-1;

    memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
    blake2b_compress(S, S->buf);

    uint8_t buffer[BLAKE2B_OUTBYTES];
    for (int i = 0; i < 8; i++)
        store64_le(buffer + 8 * i, S->h[i]);

    memcpy(out, buffer, S->outlen);
    butane_clean(buffer, BLAKE2B_OUTBYTES);
    return 0;
}

// oneshot hash function for b2b
int blake2b(void *out, size_t outlen,
            const void *in, size_t inlen,
            const void *key, size_t keylen) {
    blake2b_state S;
    int ret;

    if (key && keylen > 0)
        ret = blake2b_init_key(&S, outlen, key, keylen);
    else
        ret = blake2b_init(&S, outlen);

    if (ret != 0)
        return ret;

    ret = blake2b_update(&S, in, inlen);
    if (ret != 0)
        return ret;

    ret = blake2b_final(&S, out, outlen);
    butane_clean(&S, sizeof(S));
    return ret;
}

// varlength blake2b hash (for argon2id)
void blake2b_long(void *out, size_t outlen,
                  const void *in, size_t inlen) {
    uint8_t outlen_bytes[4];
    store32_le(outlen_bytes, (uint32_t)outlen);

    if (outlen <= BLAKE2B_OUTBYTES) {
        blake2b_state S;
        blake2b_init(&S, outlen);
        blake2b_update(&S, outlen_bytes, 4);
        blake2b_update(&S, in, inlen);
        blake2b_final(&S, out, outlen);
        butane_clean(&S, sizeof(S));
        return;
    }

    uint8_t out_buffer[BLAKE2B_OUTBYTES];
    blake2b_state S;

    blake2b_init(&S, BLAKE2B_OUTBYTES);
    blake2b_update(&S, outlen_bytes, 4);
    blake2b_update(&S, in, inlen);
    blake2b_final(&S, out_buffer, BLAKE2B_OUTBYTES);

    uint8_t *pout = (uint8_t *)out;
    memcpy(pout, out_buffer, BLAKE2B_OUTBYTES / 2);
    pout += BLAKE2B_OUTBYTES / 2;

    size_t remaining = outlen - BLAKE2B_OUTBYTES / 2;
    uint32_t toproducebytes;

    while (remaining > BLAKE2B_OUTBYTES) {
        uint8_t in_buffer[BLAKE2B_OUTBYTES];
        memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
        blake2b(out_buffer, BLAKE2B_OUTBYTES, in_buffer, BLAKE2B_OUTBYTES, NULL, 0);
        memcpy(pout, out_buffer, BLAKE2B_OUTBYTES / 2);
        pout += BLAKE2B_OUTBYTES / 2;
        remaining -= BLAKE2B_OUTBYTES / 2;
        butane_clean(in_buffer, BLAKE2B_OUTBYTES);
    }

    toproducebytes = (uint32_t)remaining;
    uint8_t in_buffer[BLAKE2B_OUTBYTES];
    memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
    blake2b(pout, toproducebytes, in_buffer, BLAKE2B_OUTBYTES, NULL, 0);

    butane_clean(in_buffer, BLAKE2B_OUTBYTES);
    butane_clean(out_buffer, BLAKE2B_OUTBYTES);
}
