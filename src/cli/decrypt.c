#include "butane.h"
#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#define MAX_PASS 256

static int read_password(const char *prompt, char *buf, size_t max) {
    fprintf(stderr, "%s", prompt);

#if defined(_WIN32)
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));

    if (!fgets(buf, (int)max, stdin)) {
        SetConsoleMode(hStdin, mode);
        return -1;
    }

    SetConsoleMode(hStdin, mode);
    fprintf(stderr, "\n");
#else
    struct termios old, noecho;
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
#endif

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';
    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\r')
        buf[len - 1] = '\0';

    return 0;
}

void cmd_decrypt(void) {
    char password[MAX_PASS];
    uint8_t salt[BUTANE_SALT_SIZE];
    uint8_t nonce[BUTANE_MAX_NONCE_SIZE];
    uint8_t tag[BUTANE_TAG_SIZE];
    uint8_t *ciphertext = NULL;
    size_t ct_len = 0;

    if (vault_read(VAULT_PATH, salt, nonce, tag, &ciphertext, &ct_len) != 0) {
        fprintf(stderr, "[error]: failed to read '%s'\n", VAULT_PATH);
        return;
    }

    if (read_password("Password: ", password, sizeof(password)) != 0) {
        fprintf(stderr, "[error]: failed to read password\n");
        goto cleanup_ct;
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

    uint8_t *plaintext = NULL;
    if (ct_len > 0) {
        plaintext = malloc(ct_len);
        if (!plaintext) {
            fprintf(stderr, "[error]: alloc failed\n");
            goto cleanup_ctx;
        }
    }

    ret = butane_decrypt(ctx, ciphertext, ct_len,
                         plaintext, nonce, tag);
    if (ret != BUTANE_OK) {
        fprintf(stderr, "[error]: decryption failed (wrong password or tampered data)\n");
        free(plaintext);
        goto cleanup_ctx;
    }

    printf("[info]: Decrypted in '%s': %.*s\n", VAULT_PATH, (int)ct_len, plaintext);

    butane_clean(plaintext, ct_len);
    free(plaintext);

cleanup_ctx:
    butane_free(ctx);
cleanup_pass:
    butane_clean(password, sizeof(password));
cleanup_ct:
    if (ciphertext) {
        butane_clean(ciphertext, ct_len);
        free(ciphertext);
    }
}
