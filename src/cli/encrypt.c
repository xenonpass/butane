#include "butane.h"
#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/random.h>

#define MAX_INPUT 4096
#define MAX_PASS  256

//read password without echo
static int read_password(const char *prompt, char *buf, size_t max) {
    struct termios old, noecho;
    fprintf(stderr, "%s", prompt);

    tcgetattr(STDIN_FILENO, &old);
    noecho = old;
    noecho.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &noecho);

    if (!fgets(buf, (int)max, stdin)) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        return -1;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    fprintf(stderr, "\n");

    // strip newline
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    return 0;
}

void cmd_encrypt(void) {
    char text[MAX_INPUT];
    char password[MAX_PASS];

    fprintf(stderr, "Text to Encrypt: ");
    if (!fgets(text, sizeof(text), stdin)) {
        fprintf(stderr, "[error]: failed to read input\n");
        return;
    }

    // strip trailing newline
    size_t text_len = strlen(text);
    if (text_len > 0 && text[text_len - 1] == '\n')
        text[--text_len] = '\0';

    if (read_password("Password: ", password, sizeof(password)) != 0) {
        fprintf(stderr, "[error]: failed to read password\n");
        return;
    }

    // generate random salt
    uint8_t salt[BUTANE_SALT_SIZE];
    if (getrandom(salt, sizeof(salt), 0) != sizeof(salt)) {
        fprintf(stderr, "[error]: entropy failure\n");
        return;
    }

    butane_t ctx = butane_init();
    if (!ctx) {
        fprintf(stderr, "[error]: init failed\n");
        goto cleanup_pass;
    }

    butane_argon2id_params params;
    butane_argon2id_default_params(&params);
    params.t_cost = 1;
    params.m_cost = 256;
    params.parallelism = 1;

    int ret = butane_derive_key(ctx,
                                (const uint8_t *)password, strlen(password),
                                salt, sizeof(salt), &params);
    if (ret != BUTANE_OK) {
        fprintf(stderr, "[error]: key derivation failed (%d)\n", ret);
        goto cleanup_ctx;
    }

    uint8_t *ciphertext = malloc(text_len);
    uint8_t nonce[BUTANE_MAX_NONCE_SIZE];
    uint8_t tag[BUTANE_TAG_SIZE];

    if (!ciphertext && text_len > 0) {
        fprintf(stderr, "[error]: alloc failed\n");
        goto cleanup_ctx;
    }

    ret = butane_encrypt(ctx, (const uint8_t *)text, text_len,
                         ciphertext, nonce, tag);
    if (ret != BUTANE_OK) {
        fprintf(stderr, "[error]: encryption failed (%d)\n", ret);
        free(ciphertext);
        goto cleanup_ctx;
    }

    if (vault_write(VAULT_PATH, salt, nonce, tag, ciphertext, text_len) != 0) {
        fprintf(stderr, "[error]: failed to write vault\n");
        free(ciphertext);
        goto cleanup_ctx;
    }

    printf("[info]: Encrypted in '%s'\n", VAULT_PATH);

    butane_clean(ciphertext, text_len);
    free(ciphertext);

cleanup_ctx:
    butane_free(ctx);
cleanup_pass:
    butane_clean(text, sizeof(text));
    butane_clean(password, sizeof(password));
}
