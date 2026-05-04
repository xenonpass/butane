#include "test_framework.h"
#include "butane.h"
#include <string.h>

static void test_init_returns_valid_handle(void) {
    butane_t ctx = butane_init();
    BT_ASSERT_NOT_NULL(ctx);
    butane_free(ctx);
}

static void test_free_null_is_safe(void) {
    butane_free(NULL);
    BT_ASSERT(1, "butane_free(NULL) did not crash");
}

static void test_clean_zeroes_memory(void) {
    uint8_t buf[64];
    memset(buf, 0xAA, sizeof(buf));
    butane_clean(buf, sizeof(buf));

    uint8_t zero[64];
    memset(zero, 0, sizeof(zero));
    BT_ASSERT_EQ_MEM(buf, zero, sizeof(buf));
}

static void test_clean_null_is_safe(void) {
    butane_clean(NULL, 100);
    BT_ASSERT(1, "butane_clean(NULL) did not crash");
}

static void test_clean_zero_length(void) {
    uint8_t buf[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    butane_clean(buf, 0);
    BT_ASSERT(buf[0] == 0xDE, "zero-length clean should not modify buffer");
}

static void test_multiple_init_free_cycles(void) {
    for (int i = 0; i < 100; i++) {
        butane_t ctx = butane_init();
        BT_ASSERT_NOT_NULL(ctx);
        butane_free(ctx);
    }
}

void run_context_tests(void) {
    BT_SUITE_BEGIN("Context Lifecycle");
    BT_RUN_TEST(test_init_returns_valid_handle);
    BT_RUN_TEST(test_free_null_is_safe);
    BT_RUN_TEST(test_clean_zeroes_memory);
    BT_RUN_TEST(test_clean_null_is_safe);
    BT_RUN_TEST(test_clean_zero_length);
    BT_RUN_TEST(test_multiple_init_free_cycles);
}
