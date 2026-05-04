#ifndef BUTANE_H
#define BUTANE_H

#include <stdint.h>
#include <stddef.h>

// codes
#define BUTANE_OK          0
#define BUTANE_ERR_NOMEM  -1
#define BUTANE_ERR_PARAM  -2
#define BUTANE_ERR_MLOCK  -3
#define BUTANE_ERR_AUTH   -4

// butane std sizes
#define BUTANE_KEY_SIZE    32
#define BUTANE_SALT_SIZE   16
#define BUTANE_TAG_SIZE    16

// aead nonce sizes
#define BUTANE_AES_GCM_NONCE_SIZE   12
#define BUTANE_XCHACHA_NONCE_SIZE   24
#define BUTANE_MAX_NONCE_SIZE       24

typedef struct butane_ctx *butane_t;

butane_t butane_init(void);
void butane_free(butane_t ctx);
void butane_clean(void *ptr, size_t len);

// query active cipher mode (returns BUTANE_CIPHER_AES256GCM or BUTANE_CIPHER_XCHACHA20)
int butane_get_cipher_mode(butane_t ctx);

// argon2id
typedef struct {
    uint32_t t_cost;
    uint32_t m_cost;
    uint32_t parallelism;
    uint32_t tag_length;
} butane_argon2id_params;

int butane_argon2id_default_params(butane_argon2id_params *params);

// derive key to context
int butane_derive_key(butane_t ctx,
                      const uint8_t *password, size_t password_len,
                      const uint8_t *salt, size_t salt_len,
                      const butane_argon2id_params *params);

// raw hash func
int butane_argon2id_hash(uint8_t *out, uint32_t out_len,
                         const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         const butane_argon2id_params *params);

// aead encrypt (dispatches to aes-256-gcm or xchacha20-poly1305)
int butane_encrypt(butane_t ctx,
                   const uint8_t *in, size_t in_len,
                   uint8_t *out,
                   uint8_t *nonce, uint8_t *tag);

// aead decrypt (dispatches to aes-256-gcm or xchacha20-poly1305)
int butane_decrypt(butane_t ctx,
                   const uint8_t *in, size_t in_len,
                   uint8_t *out,
                   const uint8_t *nonce, const uint8_t *tag);

#endif
