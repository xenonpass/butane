#include "test_framework.h"
#include "butane.h"
#include <string.h>

static void test_argon2id_default_params(void) {
    butane_argon2id_params params;
    int ret = butane_argon2id_default_params(&params);
    BT_ASSERT_EQ_INT(ret, BUTANE_OK);
    BT_ASSERT_EQ_INT(params.t_cost, 3);
    BT_ASSERT_EQ_INT(params.m_cost, 65536);
    BT_ASSERT_EQ_INT(params.parallelism, 4);
    BT_ASSERT_EQ_INT(params.tag_length, 32);
}

static void test_argon2id_default_params_null(void) {
    int ret = butane_argon2id_default_params(NULL);
    BT_ASSERT_EQ_INT(ret, BUTANE_ERR_PARAM);
}

static void test_argon2id_rfc_vector(void) {
    uint8_t password[32];
    uint8_t salt[16];
    memset(password, 0x01, 32);
    memset(salt, 0x02, 16);

    butane_argon2id_params params;
    params.t_cost      = 3;
    params.m_cost      = 32;
    params.parallelism = 4;
    params.tag_length  = 32;

    uint8_t out[32];
    int ret = butane_argon2id_hash(out, 32, password, 32, salt, 16, &params);
    BT_ASSERT_EQ_INT(ret, BUTANE_OK);

    uint8_t zero[32] = {0};
    BT_ASSERT(memcmp(out, zero, 32) != 0, "argon2id output should not be all zeros");
}

static void test_argon2id_deterministic(void) {
    const char *password = "test_password";
    const uint8_t salt[16] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00
    };

    butane_argon2id_params params;
    params.t_cost      = 1;
    params.m_cost      = 64;
    params.parallelism = 1;
    params.tag_length  = 32;

    uint8_t out1[32], out2[32];
    int r1 = butane_argon2id_hash(out1, 32,
                                   (const uint8_t *)password, strlen(password),
                                   salt, 16, &params);
    int r2 = butane_argon2id_hash(out2, 32,
                                   (const uint8_t *)password, strlen(password),
                                   salt, 16, &params);

    BT_ASSERT_EQ_INT(r1, BUTANE_OK);
    BT_ASSERT_EQ_INT(r2, BUTANE_OK);
    BT_ASSERT_EQ_MEM(out1, out2, 32);
}

static void test_argon2id_different_passwords(void) {
    const uint8_t salt[16] = {0};

    butane_argon2id_params params;
    params.t_cost      = 1;
    params.m_cost      = 64;
    params.parallelism = 1;
    params.tag_length  = 32;

    uint8_t out1[32], out2[32];
    const char *pw1 = "password1";
    const char *pw2 = "password2";

    butane_argon2id_hash(out1, 32, (const uint8_t *)pw1, strlen(pw1),
                         salt, 16, &params);
    butane_argon2id_hash(out2, 32, (const uint8_t *)pw2, strlen(pw2),
                         salt, 16, &params);

    BT_ASSERT(memcmp(out1, out2, 32) != 0,
              "different passwords must produce different hashes");
}

static void test_argon2id_different_salts(void) {
    const char *password = "_the_same_password_";

    butane_argon2id_params params;
    params.t_cost      = 1;
    params.m_cost      = 64;
    params.parallelism = 1;
    params.tag_length  = 32;

    uint8_t salt1[16], salt2[16];
    memset(salt1, 0xAA, 16);
    memset(salt2, 0xBB, 16);

    uint8_t out1[32], out2[32];
    butane_argon2id_hash(out1, 32, (const uint8_t *)password, strlen(password),
                         salt1, 16, &params);
    butane_argon2id_hash(out2, 32, (const uint8_t *)password, strlen(password),
                         salt2, 16, &params);

    BT_ASSERT(memcmp(out1, out2, 32) != 0,
              "different salts must produce different hashes");
}

static void test_argon2id_null_output(void) {
    butane_argon2id_params params;
    butane_argon2id_default_params(&params);
    uint8_t salt[16] = {0};

    int ret = butane_argon2id_hash(NULL, 32, (const uint8_t *)"pw", 2,
                                   salt, 16, &params);
    BT_ASSERT_EQ_INT(ret, BUTANE_ERR_PARAM);
}

static void test_argon2id_short_salt(void) {
    butane_argon2id_params params;
    butane_argon2id_default_params(&params);
    uint8_t out[32];
    uint8_t salt[4] = {0};

    int ret = butane_argon2id_hash(out, 32, (const uint8_t *)"pw", 2,
                                   salt, 4, &params);
    BT_ASSERT_EQ_INT(ret, BUTANE_ERR_PARAM);
}

static void test_argon2id_zero_iterations(void) {
    butane_argon2id_params params;
    butane_argon2id_default_params(&params);
    params.t_cost = 0;
    uint8_t out[32];
    uint8_t salt[16] = {0};

    int ret = butane_argon2id_hash(out, 32, (const uint8_t *)"pw", 2,
                                   salt, 16, &params);
    BT_ASSERT_EQ_INT(ret, BUTANE_ERR_PARAM);
}

static void test_derive_key_basic(void) {
    butane_t ctx = butane_init();
    BT_ASSERT_NOT_NULL(ctx);

    const char *password = "_a_master_password_";
    uint8_t salt[16];
    memset(salt, 0x42, 16);

    butane_argon2id_params params;
    params.t_cost      = 1;
    params.m_cost      = 64;
    params.parallelism = 1;
    params.tag_length  = 32;

    int ret = butane_derive_key(ctx,
                                (const uint8_t *)password, strlen(password),
                                salt, 16, &params);
    BT_ASSERT_EQ_INT(ret, BUTANE_OK);

    butane_free(ctx);
}

static void test_derive_key_null_ctx(void) {
    uint8_t salt[16] = {0};
    butane_argon2id_params params;
    butane_argon2id_default_params(&params);

    int ret = butane_derive_key(NULL, (const uint8_t *)"pw", 2,
                                salt, 16, &params);
    BT_ASSERT_EQ_INT(ret, BUTANE_ERR_PARAM);
}

void run_argon2id_tests(void) {
    BT_SUITE_BEGIN("Argon2id");
    BT_RUN_TEST(test_argon2id_default_params);
    BT_RUN_TEST(test_argon2id_default_params_null);
    BT_RUN_TEST(test_argon2id_rfc_vector);
    BT_RUN_TEST(test_argon2id_deterministic);
    BT_RUN_TEST(test_argon2id_different_passwords);
    BT_RUN_TEST(test_argon2id_different_salts);
    BT_RUN_TEST(test_argon2id_null_output);
    BT_RUN_TEST(test_argon2id_short_salt);
    BT_RUN_TEST(test_argon2id_zero_iterations);
    BT_RUN_TEST(test_derive_key_basic);
    BT_RUN_TEST(test_derive_key_null_ctx);
}
