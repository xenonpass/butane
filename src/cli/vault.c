#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int vault_write(const char *path,
                const uint8_t *salt,
                const uint8_t *nonce,
                const uint8_t *tag,
                const uint8_t *ciphertext, size_t ct_len) {
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return -1;

    if (fwrite(salt, 1, BUTANE_SALT_SIZE, fp) != BUTANE_SALT_SIZE)
        goto fail;
    if (fwrite(nonce, 1, BUTANE_MAX_NONCE_SIZE, fp) != BUTANE_MAX_NONCE_SIZE)
        goto fail;
    if (fwrite(tag, 1, BUTANE_TAG_SIZE, fp) != BUTANE_TAG_SIZE)
        goto fail;
    if (ct_len > 0 && fwrite(ciphertext, 1, ct_len, fp) != ct_len)
        goto fail;

    fclose(fp);
    return 0;

fail:
    fclose(fp);
    return -1;
}

int vault_read(const char *path,
               uint8_t *salt,
               uint8_t *nonce,
               uint8_t *tag,
               uint8_t **ciphertext, size_t *ct_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    // get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size < VAULT_HEADER_SIZE) {
        fclose(fp);
        return -1;
    }

    if (fread(salt, 1, BUTANE_SALT_SIZE, fp) != BUTANE_SALT_SIZE)
        goto fail;
    if (fread(nonce, 1, BUTANE_MAX_NONCE_SIZE, fp) != BUTANE_MAX_NONCE_SIZE)
        goto fail;
    if (fread(tag, 1, BUTANE_TAG_SIZE, fp) != BUTANE_TAG_SIZE)
        goto fail;

    *ct_len = (size_t)(file_size - VAULT_HEADER_SIZE);
    if (*ct_len > 0) {
        *ciphertext = malloc(*ct_len);
        if (!*ciphertext)
            goto fail;
        if (fread(*ciphertext, 1, *ct_len, fp) != *ct_len) {
            free(*ciphertext);
            *ciphertext = NULL;
            goto fail;
        }
    } else {
        *ciphertext = NULL;
    }

    fclose(fp);
    return 0;

fail:
    fclose(fp);
    return -1;
}
