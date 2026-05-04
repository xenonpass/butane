#ifndef BUTANE_CHACHA20_H
#define BUTANE_CHACHA20_H

#include <stdint.h>
#include <stddef.h>

#define CHACHA20_KEY_SIZE     32
#define CHACHA20_NONCE_SIZE   12
#define XCHACHA20_NONCE_SIZE  24
#define POLY1305_TAG_SIZE     16

// raw chacha20 keystream xor
void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                  const uint8_t *key, const uint8_t *nonce,
                  uint32_t initial_counter);

// hchacha20 core for xchacha20 subkey derivation
void hchacha20(uint8_t *subkey, const uint8_t *key, const uint8_t *nonce16);

// poly1305 one-shot mac
void poly1305_auth(uint8_t *tag, const uint8_t *msg, size_t msg_len,
                   const uint8_t *key32);

// xchacha20-poly1305 aead encrypt
int xchacha20poly1305_encrypt(const uint8_t *key,
                              const uint8_t *nonce24,
                              const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t *ciphertext,
                              uint8_t *tag16);

// xchacha20-poly1305 aead decrypt
int xchacha20poly1305_decrypt(const uint8_t *key,
                              const uint8_t *nonce24,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext,
                              const uint8_t *tag16);

#endif
