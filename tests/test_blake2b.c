#include "test_framework.h"
#include "blake2b.h"
#include <string.h>

static void test_blake2b_empty_input(void) {
    uint8_t out[64];
    uint8_t expected[64] = {
        0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03,
        0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52, 0xd2, 0x72,
        0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61,
        0x8a, 0x86, 0xe2, 0x17, 0xf7, 0x1f, 0x54, 0x19,
        0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53,
        0x13, 0x89, 0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b,
        0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
        0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce
    };

    int ret = blake2b(out, 64, NULL, 0, NULL, 0);
    BT_ASSERT_EQ_INT(ret, 0);
    BT_ASSERT_EQ_MEM(out, expected, 64);
}

static void test_blake2b_abc(void) {
    uint8_t out[64];
    const char *input = "abc";
    uint8_t expected[64] = {
        0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d,
        0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
        0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7,
        0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
        0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d,
        0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
        0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
        0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23
    };

    int ret = blake2b(out, 64, input, 3, NULL, 0);
    BT_ASSERT_EQ_INT(ret, 0);
    BT_ASSERT_EQ_MEM(out, expected, 64);
}

static void test_blake2b_32byte_output(void) {
    uint8_t out[32];
    const char *input = "abc";
    uint8_t expected[32] = {
        0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72,
        0x31, 0x71, 0xef, 0x3f, 0xee, 0x98, 0x57, 0x9b,
        0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42,
        0x72, 0x62, 0xc8, 0xc0, 0x68, 0xd5, 0x23, 0x19
    };

    int ret = blake2b(out, 32, input, 3, NULL, 0);
    BT_ASSERT_EQ_INT(ret, 0);
    BT_ASSERT_EQ_MEM(out, expected, 32);
}

static void test_blake2b_incremental(void) {
    uint8_t out_oneshot[64];
    uint8_t out_incremental[64];
    const char *input = "tonights the night, and i need it.";
    size_t len = strlen(input);

    blake2b(out_oneshot, 64, input, len, NULL, 0);

    blake2b_state S;
    blake2b_init(&S, 64);
    blake2b_update(&S, input, 10);
    blake2b_update(&S, input + 10, len - 10);
    blake2b_final(&S, out_incremental, 64);

    BT_ASSERT_EQ_MEM(out_oneshot, out_incremental, 64);
}

static void test_blake2b_invalid_outlen(void) {
    uint8_t out[1];
    int ret = blake2b(out, 0, NULL, 0, NULL, 0);
    BT_ASSERT_EQ_INT(ret, -1);
}

static void test_blake2b_keyed(void) {
    uint8_t key[64];
    for (int i = 0; i < 64; i++)
        key[i] = (uint8_t)i;

    uint8_t out[64];
    int ret = blake2b(out, 64, NULL, 0, key, 64);
    BT_ASSERT_EQ_INT(ret, 0);

    uint8_t zero[64] = {0};
    BT_ASSERT(memcmp(out, zero, 64) != 0, "keyed hash should not be all zeros");
}

void run_blake2b_tests(void) {
    BT_SUITE_BEGIN("Blake2b");
    BT_RUN_TEST(test_blake2b_empty_input);
    BT_RUN_TEST(test_blake2b_abc);
    BT_RUN_TEST(test_blake2b_32byte_output);
    BT_RUN_TEST(test_blake2b_incremental);
    BT_RUN_TEST(test_blake2b_invalid_outlen);
    BT_RUN_TEST(test_blake2b_keyed);
}
