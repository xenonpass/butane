#include "butane.h"
#include "internal.h"
#include "aes256gcm.h"
#include "chacha20.h"
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(_WIN32)
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

// fill buffer with cryptographically secure random bytes
int secure_random_fill(uint8_t *buf, size_t len) {
#if defined(__linux__)
    // linux
    ssize_t result = getrandom(buf, len, 0);
    return (result == (ssize_t)len) ? 0 : -1;
#elif defined(__APPLE__)
    // apple
    return SecRandomCopyBytes(kSecRandomDefault, len, buf);
#elif defined(_WIN32)
    // windows
    return BCryptGenRandom(NULL, buf, (ULONG)len,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t result = read(fd, buf, len);
    close(fd);
    return (result == (ssize_t)len) ? 0 : -1;
#endif
}

int butane_encrypt(butane_t ctx,
                   const uint8_t *in, size_t in_len,
                   uint8_t *out,
                   uint8_t *nonce, uint8_t *tag) {
    if (!ctx || !(ctx->flags & BUTANE_FLAG_KEY_DERIVED))
        return BUTANE_ERR_PARAM;
    if (!nonce || !tag)
        return BUTANE_ERR_PARAM;
    if (in_len > 0 && (!in || !out))
        return BUTANE_ERR_PARAM;

    if (ctx->cipher_mode == BUTANE_CIPHER_AES256GCM) {
        // generate 12-byte random nonce for aes-gcm
        if (secure_random_fill(nonce, BUTANE_AES_GCM_NONCE_SIZE) != 0)
            return BUTANE_ERR_PARAM;
        return aes256gcm_encrypt(ctx->master_key, nonce, in, in_len, out, tag);
    }

    // fallback to xchacha20-poly1305
    if (secure_random_fill(nonce, BUTANE_XCHACHA_NONCE_SIZE) != 0)
        return BUTANE_ERR_PARAM;
    return xchacha20poly1305_encrypt(ctx->master_key, nonce, in, in_len, out, tag);
}

int butane_decrypt(butane_t ctx,
                   const uint8_t *in, size_t in_len,
                   uint8_t *out,
                   const uint8_t *nonce, const uint8_t *tag) {
    if (!ctx || !(ctx->flags & BUTANE_FLAG_KEY_DERIVED))
        return BUTANE_ERR_PARAM;
    if (!nonce || !tag)
        return BUTANE_ERR_PARAM;
    if (in_len > 0 && (!in || !out))
        return BUTANE_ERR_PARAM;

    if (ctx->cipher_mode == BUTANE_CIPHER_AES256GCM)
        return aes256gcm_decrypt(ctx->master_key, nonce, in, in_len, out, tag);

    return xchacha20poly1305_decrypt(ctx->master_key, nonce, in, in_len, out, tag);
}
