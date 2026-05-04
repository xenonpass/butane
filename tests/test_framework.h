#ifndef BUTANE_TEST_FRAMEWORK_H
#define BUTANE_TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern int _bt_tests_run;
extern int _bt_tests_passed;
extern int _bt_tests_failed;

#define BT_ASSERT(cond, msg) do {                                           \
    if (!(cond)) {                                                          \
        printf("    ASSERTION FAILED at %s:%d: %s\n", __FILE__, __LINE__,   \
               (msg));                                                      \
        _bt_tests_failed++;                                                 \
        return;                                                             \
    }                                                                       \
} while(0)

#define BT_ASSERT_EQ_INT(actual, expected) do {                             \
    int _a = (int)(actual), _e = (int)(expected);                           \
    if (_a != _e) {                                                         \
        printf("    ASSERTION FAILED at %s:%d: expected %d, got %d\n",      \
               __FILE__, __LINE__, _e, _a);                                 \
        _bt_tests_failed++;                                                 \
        return;                                                             \
    }                                                                       \
} while(0)

#define BT_ASSERT_EQ_MEM(actual, expected, len) do {                        \
    if (memcmp((actual), (expected), (len)) != 0) {                         \
        printf("    ASSERTION FAILED at %s:%d: memory mismatch (%zu bytes)\n", \
               __FILE__, __LINE__, (size_t)(len));                          \
        const unsigned char *_pa = (const unsigned char *)(actual);         \
        const unsigned char *_pe = (const unsigned char *)(expected);       \
        printf("      expected: ");                                         \
        for (size_t _i = 0; _i < (size_t)(len) && _i < 32; _i++)           \
            printf("%02x", _pe[_i]);                                        \
        printf("\n      actual:   ");                                       \
        for (size_t _i = 0; _i < (size_t)(len) && _i < 32; _i++)           \
            printf("%02x", _pa[_i]);                                        \
        printf("\n");                                                       \
        _bt_tests_failed++;                                                 \
        return;                                                             \
    }                                                                       \
} while(0)

#define BT_ASSERT_NOT_NULL(ptr) do {                                        \
    if ((ptr) == NULL) {                                                    \
        printf("    ASSERTION FAILED at %s:%d: unexpected NULL\n",          \
               __FILE__, __LINE__);                                         \
        _bt_tests_failed++;                                                 \
        return;                                                             \
    }                                                                       \
} while(0)

#define BT_ASSERT_NULL(ptr) do {                                            \
    if ((ptr) != NULL) {                                                    \
        printf("    ASSERTION FAILED at %s:%d: expected NULL\n",            \
               __FILE__, __LINE__);                                         \
        _bt_tests_failed++;                                                 \
        return;                                                             \
    }                                                                       \
} while(0)

#define BT_RUN_TEST(test_fn) do {                                           \
    int _prev_failed = _bt_tests_failed;                                    \
    _bt_tests_run++;                                                        \
    test_fn();                                                              \
    if (_bt_tests_failed == _prev_failed) {                                 \
        _bt_tests_passed++;                                                 \
        printf("  [ PASS ] %s\n", #test_fn);                               \
    } else {                                                                \
        printf("  [ FAIL ] %s\n", #test_fn);                               \
    }                                                                       \
} while(0)

#define BT_SUITE_BEGIN(name) do {                                           \
    printf("\n=== Suite: %s ===\n", (name));                                \
} while(0)

#define BT_REPORT() do {                                                    \
    printf("\n=========================================\n");                \
    printf("  Total: %d | Passed: %d | Failed: %d\n",                      \
           _bt_tests_run, _bt_tests_passed, _bt_tests_failed);             \
    printf("=========================================\n\n");               \
} while(0)

#define BT_EXIT_CODE() (_bt_tests_failed > 0 ? 1 : 0)

#endif
