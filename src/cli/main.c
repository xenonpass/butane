#include "butane.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cmd_encrypt(void);
void cmd_decrypt(void);

static void usage(const char *prog) {
    fprintf(stderr, "usage: %s <encrypt|decrypt>\n", prog);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "encrypt") == 0) {
        cmd_encrypt();
    } else if (strcmp(argv[1], "decrypt") == 0) {
        cmd_decrypt();
    } else {
        usage(argv[0]);
        return 1;
    }

    return 0;
}
