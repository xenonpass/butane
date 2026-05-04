#include "test_framework.h"

int _bt_tests_run    = 0;
int _bt_tests_passed = 0;
int _bt_tests_failed = 0;

extern void run_context_tests(void);
extern void run_blake2b_tests(void);
extern void run_argon2id_tests(void);

int main(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════════╗\n");
    printf("  ║           BUTANE test suite          ║\n");
    printf("  ╚══════════════════════════════════════╝\n");

    run_context_tests();
    run_blake2b_tests();
    run_argon2id_tests();

    BT_REPORT();
    return BT_EXIT_CODE();
}
