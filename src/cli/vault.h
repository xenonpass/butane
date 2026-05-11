#ifndef VAULT_H
#define VAULT_H

#include "butane.h"
#include <stdint.h>
#include <stddef.h>

#define VAULT_PATH "tests/vault/test.butane"

// vault file layout (all little-endian):
// -> [salt: 16] [nonce: 24] [tag: 16] [ciphertext: rest]
#define VAULT_HEADER_SIZE (BUTANE_SALT_SIZE + BUTANE_MAX_NONCE_SIZE + BUTANE_TAG_SIZE)

int vault_write(const char *path,
                const uint8_t *salt,
                const uint8_t *nonce,
                const uint8_t *tag,
                const uint8_t *ciphertext, size_t ct_len);

// caller must free *ciphertext after use
int vault_read(const char *path,
               uint8_t *salt,
               uint8_t *nonce,
               uint8_t *tag,
               uint8_t **ciphertext, size_t *ct_len);

#endif
