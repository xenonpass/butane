#ifndef BUTANE_AES256GCM_H
#define BUTANE_AES256GCM_H

#include <stddef.h>
#include <stdint.h>

#define AES256_KEY_SIZE 32
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16

// aes-256-gcm encrypt using aes-ni intrinsics
int aes256gcm_encrypt(const uint8_t *key, const uint8_t *iv12,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint8_t *ciphertext, uint8_t *tag16);

// aes-256-gcm decrypt using aes-ni intrinsics
int aes256gcm_decrypt(const uint8_t *key, const uint8_t *iv12,
                      const uint8_t *ciphertext, size_t ciphertext_len,
                      uint8_t *plaintext, const uint8_t *tag16);

#endif
