#ifndef BUTANE_INTERNAL_H
#define BUTANE_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

// flags
#define BUTANE_FLAG_INITIALIZED  0x01
#define BUTANE_FLAG_KEY_DERIVED  0x02

// cipher mode identifiers
#define BUTANE_CIPHER_AES256GCM     1
#define BUTANE_CIPHER_XCHACHA20     2

// internal contxt def
struct butane_ctx {
    uint8_t  master_key[BUTANE_KEY_SIZE];
    uint8_t  salt[BUTANE_SALT_SIZE];
    uint32_t flags;
    int      cipher_mode;
    int      memory_locked;
};

#endif
