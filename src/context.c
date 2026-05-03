#include "butane.h"
#include "internal.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

// alloc and init new contxt
butane_t butane_init(void) {
    struct butane_ctx *ctx = malloc(sizeof(struct butane_ctx));
    if (!ctx)
        return NULL;

    memset(ctx, 0, sizeof(struct butane_ctx));

    // lock sensitive mem
    if (mlock(ctx, sizeof(struct butane_ctx)) == 0) {
        ctx->memory_locked = 1;
    } else {
        ctx->memory_locked = 0;
    }

    ctx->flags = BUTANE_FLAG_INITIALIZED;
    return ctx;
}

// free contxt and wipe important stuff
void butane_free(butane_t ctx) {
    if (!ctx)
        return;

    butane_clean(ctx->master_key, BUTANE_KEY_SIZE);
    butane_clean(ctx->salt, BUTANE_SALT_SIZE);
    ctx->flags = 0;

    // unlock if successfully locked
    if (ctx->memory_locked)
        munlock(ctx, sizeof(struct butane_ctx));

    butane_clean(ctx, sizeof(struct butane_ctx));
    free(ctx);
}
