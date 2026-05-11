#include "butane.h"
#include "internal.h"
#include "blake2b.h"
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <memoryapi.h>
#else
#include <sys/mman.h>
#endif

#define ARGON2_BLOCK_SIZE     1024
#define ARGON2_QWORDS_IN_BLOCK 128
#define ARGON2_VERSION        0x13
#define ARGON2_TYPE_ID        2
#define ARGON2_SYNC_POINTS    4
#define ARGON2_PREHASH_DIGEST_LENGTH 64
#define ARGON2_PREHASH_SEED_LENGTH   72

typedef struct {
    uint64_t v[ARGON2_QWORDS_IN_BLOCK];
} block;

// internal state tracking during memory filling
typedef struct {
    block *memory;
    uint32_t memory_blocks;
    uint32_t segment_length;
    uint32_t lane_length;
    uint32_t lanes;
    uint32_t passes;
} argon2_instance;

static inline uint64_t load64_le(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint64_t)p[0])       | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void store32_le(void *dst, uint32_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(w);
    p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
}

static inline uint64_t fBlaMka(uint64_t x, uint64_t y) {
    uint64_t m = 0xFFFFFFFFULL;
    uint64_t xy = (x & m) * (y & m);
    return x + y + 2 * xy;
}

static inline uint64_t rotr64(uint64_t x, unsigned int n) {
    return (x >> n) | (x << (64 - n));
}

#define GB(a, b, c, d) do {    \
    a = fBlaMka(a, b);         \
    d = rotr64(d ^ a, 32);     \
    c = fBlaMka(c, d);         \
    b = rotr64(b ^ c, 24);     \
    a = fBlaMka(a, b);         \
    d = rotr64(d ^ a, 16);     \
    c = fBlaMka(c, d);         \
    b = rotr64(b ^ c, 63);     \
} while(0)

#define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, \
                           v8, v9, v10, v11, v12, v13, v14, v15) do { \
    GB(v0, v4, v8,  v12); \
    GB(v1, v5, v9,  v13); \
    GB(v2, v6, v10, v14); \
    GB(v3, v7, v11, v15); \
    GB(v0, v5, v10, v15); \
    GB(v1, v6, v11, v12); \
    GB(v2, v7, v8,  v13); \
    GB(v3, v4, v9,  v14); \
} while(0)

static void fill_block(const block *prev, const block *ref, block *next, int with_xor) {
    block blockR, blockTmp;

    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++)
        blockR.v[i] = prev->v[i] ^ ref->v[i];

    memcpy(&blockTmp, &blockR, sizeof(block));

    for (int i = 0; i < 8; i++) {
        BLAKE2_ROUND_NOMSG(
            blockR.v[16 * i + 0],  blockR.v[16 * i + 1],
            blockR.v[16 * i + 2],  blockR.v[16 * i + 3],
            blockR.v[16 * i + 4],  blockR.v[16 * i + 5],
            blockR.v[16 * i + 6],  blockR.v[16 * i + 7],
            blockR.v[16 * i + 8],  blockR.v[16 * i + 9],
            blockR.v[16 * i + 10], blockR.v[16 * i + 11],
            blockR.v[16 * i + 12], blockR.v[16 * i + 13],
            blockR.v[16 * i + 14], blockR.v[16 * i + 15]
        );
    }

    for (int i = 0; i < 8; i++) {
        BLAKE2_ROUND_NOMSG(
            blockR.v[2 * i + 0],  blockR.v[2 * i + 1],
            blockR.v[2 * i + 16], blockR.v[2 * i + 17],
            blockR.v[2 * i + 32], blockR.v[2 * i + 33],
            blockR.v[2 * i + 48], blockR.v[2 * i + 49],
            blockR.v[2 * i + 64], blockR.v[2 * i + 65],
            blockR.v[2 * i + 80], blockR.v[2 * i + 81],
            blockR.v[2 * i + 96], blockR.v[2 * i + 97],
            blockR.v[2 * i + 112], blockR.v[2 * i + 113]
        );
    }

    if (with_xor) {
        for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++)
            next->v[i] ^= blockR.v[i] ^ blockTmp.v[i];
    } else {
        for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++)
            next->v[i] = blockR.v[i] ^ blockTmp.v[i];
    }
}

static uint32_t index_alpha(const argon2_instance *inst,
                             uint32_t pass, uint32_t slice,
                             uint32_t lane, uint32_t index,
                             uint32_t pseudo_rand,
                             int same_lane) {
    uint32_t reference_area_size;

    if (pass == 0) {
        if (slice == 0) {
            reference_area_size = index - 1;
        } else {
            if (same_lane)
                reference_area_size = slice * inst->segment_length + index - 1;
            else
                reference_area_size = slice * inst->segment_length + ((index == 0) ? (uint32_t)-1 : 0);
        }
    } else {
        if (same_lane)
            reference_area_size = inst->lane_length - inst->segment_length + index - 1;
        else
            reference_area_size = inst->lane_length - inst->segment_length + ((index == 0) ? (uint32_t)-1 : 0);
    }

    uint64_t relative_position = (uint64_t)pseudo_rand * (uint64_t)pseudo_rand >> 32;
    relative_position = reference_area_size - 1 - (uint64_t)(reference_area_size * relative_position >> 32);

    uint32_t start_position = 0;
    if (pass != 0)
        start_position = (slice == ARGON2_SYNC_POINTS - 1) ? 0 : (slice + 1) * inst->segment_length;

    (void)lane;
    return (uint32_t)((start_position + relative_position) % inst->lane_length);
}

// generate addressing blocks for independent memory accesses
static void generate_addresses(const argon2_instance *inst,
                                uint32_t pass, uint32_t lane, uint32_t slice,
                                block *pseudo_rands) {
    block input_block, address_block, zero_block;
    memset(&zero_block, 0, sizeof(block));
    memset(&input_block, 0, sizeof(block));
    memset(&address_block, 0, sizeof(block));

    input_block.v[0] = pass;
    input_block.v[1] = lane;
    input_block.v[2] = slice;
    input_block.v[3] = inst->memory_blocks;
    input_block.v[4] = inst->passes;
    input_block.v[5] = ARGON2_TYPE_ID;

    for (uint32_t i = 0; i < inst->segment_length; i++) {
        if (i % ARGON2_QWORDS_IN_BLOCK == 0) {
            input_block.v[6]++;
            fill_block(&zero_block, &input_block, &address_block, 0);
            fill_block(&zero_block, &address_block, &address_block, 0);
        }
        pseudo_rands->v[i % ARGON2_QWORDS_IN_BLOCK] = address_block.v[i % ARGON2_QWORDS_IN_BLOCK];
    }
}

// fill part of argon2 memory
static void fill_segment(const argon2_instance *inst,
                           uint32_t pass, uint32_t lane, uint32_t slice) {
    int data_independent = (pass == 0 && slice < 2);

    block pseudo_rands_block;
    if (data_independent)
        generate_addresses(inst, pass, lane, slice, &pseudo_rands_block);

    uint32_t starting_index = 0;
    if (pass == 0 && slice == 0)
        starting_index = 2;

    uint32_t curr_offset = lane * inst->lane_length + slice * inst->segment_length + starting_index;
    uint32_t prev_offset = curr_offset - 1;

    for (uint32_t i = starting_index; i < inst->segment_length; i++, curr_offset++, prev_offset++) {
        if (curr_offset % inst->lane_length == 0)
            prev_offset = curr_offset + inst->lane_length - 1;

        uint64_t pseudo_rand;
        if (data_independent)
            pseudo_rand = pseudo_rands_block.v[i % ARGON2_QWORDS_IN_BLOCK];
        else
            pseudo_rand = inst->memory[prev_offset].v[0];

        uint32_t ref_lane = (uint32_t)((pseudo_rand >> 32) % inst->lanes);

        if (pass == 0 && slice == 0)
            ref_lane = lane;

        uint32_t ref_index = index_alpha(inst, pass, slice, lane, i,
                                          (uint32_t)(pseudo_rand & 0xFFFFFFFF),
                                          ref_lane == lane);

        uint32_t ref_block_index = ref_lane * inst->lane_length + ref_index;

        fill_block(&inst->memory[prev_offset], &inst->memory[ref_block_index],
                   &inst->memory[curr_offset], pass != 0);
    }
}

// make initial h0 hash
static void initial_hash(uint8_t *blockhash,
                          const uint8_t *password, size_t password_len,
                          const uint8_t *salt, size_t salt_len,
                          const butane_argon2id_params *params) {
    blake2b_state S;
    uint8_t value[4];

    blake2b_init(&S, ARGON2_PREHASH_DIGEST_LENGTH);

    store32_le(value, params->parallelism);
    blake2b_update(&S, value, 4);

    store32_le(value, params->tag_length);
    blake2b_update(&S, value, 4);

    store32_le(value, params->m_cost);
    blake2b_update(&S, value, 4);

    store32_le(value, params->t_cost);
    blake2b_update(&S, value, 4);

    store32_le(value, ARGON2_VERSION);
    blake2b_update(&S, value, 4);

    store32_le(value, ARGON2_TYPE_ID);
    blake2b_update(&S, value, 4);

    store32_le(value, (uint32_t)password_len);
    blake2b_update(&S, value, 4);
    if (password_len > 0)
        blake2b_update(&S, password, password_len);

    store32_le(value, (uint32_t)salt_len);
    blake2b_update(&S, value, 4);
    if (salt_len > 0)
        blake2b_update(&S, salt, salt_len);

    store32_le(value, 0);
    blake2b_update(&S, value, 4);

    store32_le(value, 0);
    blake2b_update(&S, value, 4);

    blake2b_final(&S, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
    butane_clean(&S, sizeof(S));
}

static void fill_first_blocks(argon2_instance *inst, uint8_t *blockhash) {
    uint8_t blockhash_bytes[ARGON2_PREHASH_SEED_LENGTH];
    memcpy(blockhash_bytes, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);

    for (uint32_t l = 0; l < inst->lanes; l++) {
        store32_le(blockhash_bytes + ARGON2_PREHASH_DIGEST_LENGTH, 0);
        store32_le(blockhash_bytes + ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
        blake2b_long(inst->memory[l * inst->lane_length].v,
                     ARGON2_BLOCK_SIZE,
                     blockhash_bytes, ARGON2_PREHASH_SEED_LENGTH);

        store32_le(blockhash_bytes + ARGON2_PREHASH_DIGEST_LENGTH, 1);
        blake2b_long(inst->memory[l * inst->lane_length + 1].v,
                     ARGON2_BLOCK_SIZE,
                     blockhash_bytes, ARGON2_PREHASH_SEED_LENGTH);
    }

    butane_clean(blockhash_bytes, ARGON2_PREHASH_SEED_LENGTH);
}

static void finalize(uint8_t *out, uint32_t outlen, const argon2_instance *inst) {
    block blockhash;
    memcpy(&blockhash, &inst->memory[inst->lane_length - 1], sizeof(block));

    for (uint32_t l = 1; l < inst->lanes; l++) {
        uint32_t last_block_in_lane = l * inst->lane_length + (inst->lane_length - 1);
        for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++)
            blockhash.v[i] ^= inst->memory[last_block_in_lane].v[i];
    }

    blake2b_long(out, outlen, blockhash.v, ARGON2_BLOCK_SIZE);
    butane_clean(&blockhash, sizeof(block));
}

// get default argon2id parameters
int butane_argon2id_default_params(butane_argon2id_params *params) {
    if (!params)
        return BUTANE_ERR_PARAM;

    params->t_cost      = 3;
    params->m_cost      = 65536;
    params->parallelism = 4;
    params->tag_length  = 32;
    return BUTANE_OK;
}

// process raw argon2id hash
int butane_argon2id_hash(uint8_t *out, uint32_t out_len,
                         const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         const butane_argon2id_params *params) {
    if (!out || out_len < 4)
        return BUTANE_ERR_PARAM;
    if (!salt || salt_len < 8)
        return BUTANE_ERR_PARAM;
    if (!params || params->t_cost == 0 || params->parallelism == 0)
        return BUTANE_ERR_PARAM;
    if (params->m_cost < 8 * params->parallelism)
        return BUTANE_ERR_PARAM;

    argon2_instance inst;
    inst.lanes = params->parallelism;
    inst.passes = params->t_cost;

    uint32_t memory_blocks = params->m_cost;
    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * params->parallelism)
        memory_blocks = 2 * ARGON2_SYNC_POINTS * params->parallelism;

    inst.segment_length = memory_blocks / (inst.lanes * ARGON2_SYNC_POINTS);
    inst.lane_length = inst.segment_length * ARGON2_SYNC_POINTS;
    inst.memory_blocks = inst.lane_length * inst.lanes;

    inst.memory = calloc(inst.memory_blocks, sizeof(block));
    if (!inst.memory)
        return BUTANE_ERR_NOMEM;

#if defined(_WIN32)
    VirtualLock(inst.memory, (SIZE_T)inst.memory_blocks * sizeof(block));
#else
    mlock(inst.memory, (size_t)inst.memory_blocks * sizeof(block));
#endif

    uint8_t blockhash[ARGON2_PREHASH_DIGEST_LENGTH];
    initial_hash(blockhash, password, password_len, salt, salt_len, params);
    fill_first_blocks(&inst, blockhash);
    butane_clean(blockhash, ARGON2_PREHASH_DIGEST_LENGTH);

    for (uint32_t pass = 0; pass < inst.passes; pass++) {
        for (uint32_t slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
            for (uint32_t lane = 0; lane < inst.lanes; lane++) {
                fill_segment(&inst, pass, lane, slice);
            }
        }
    }

    finalize(out, out_len, &inst);

#if defined(_WIN32)
    VirtualUnlock(inst.memory, (SIZE_T)inst.memory_blocks * sizeof(block));
#else
    munlock(inst.memory, (size_t)inst.memory_blocks * sizeof(block));
#endif
    butane_clean(inst.memory, (size_t)inst.memory_blocks * sizeof(block));
    free(inst.memory);

    return BUTANE_OK;
}

// derive a strong key for butane's context
int butane_derive_key(butane_t ctx,
                      const uint8_t *password, size_t password_len,
                      const uint8_t *salt, size_t salt_len,
                      const butane_argon2id_params *params) {
    if (!ctx || !(ctx->flags & BUTANE_FLAG_INITIALIZED))
        return BUTANE_ERR_PARAM;

    butane_argon2id_params p;
    if (params) {
        p = *params;
    } else {
        butane_argon2id_default_params(&p);
    }
    p.tag_length = BUTANE_KEY_SIZE;

    int ret = butane_argon2id_hash(ctx->master_key, BUTANE_KEY_SIZE,
                                   password, password_len,
                                   salt, salt_len, &p);
    if (ret == BUTANE_OK) {
        if (salt && salt_len >= BUTANE_SALT_SIZE)
            memcpy(ctx->salt, salt, BUTANE_SALT_SIZE);
        ctx->flags |= BUTANE_FLAG_KEY_DERIVED;
    }

    return ret;
}
