#ifndef BUTANE_BLAKE2B_H
#define BUTANE_BLAKE2B_H

#include <stdint.h>
#include <stddef.h>

#define BLAKE2B_BLOCKBYTES  128
#define BLAKE2B_OUTBYTES     64
#define BLAKE2B_KEYBYTES     64

typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
} blake2b_state;

int blake2b_init(blake2b_state *S, size_t outlen);
int blake2b_init_key(blake2b_state *S, size_t outlen,
                     const void *key, size_t keylen);
int blake2b_update(blake2b_state *S, const void *in, size_t inlen);
int blake2b_final(blake2b_state *S, void *out, size_t outlen);

int blake2b(void *out, size_t outlen,
            const void *in, size_t inlen,
            const void *key, size_t keylen);

void blake2b_long(void *out, size_t outlen,
                  const void *in, size_t inlen);

#endif
