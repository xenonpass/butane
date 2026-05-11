#include "butane.h"
#include "hwdetect.h"
#include "internal.h"
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <memoryapi.h>
#else
#include <sys/mman.h>
#endif

// alloc and init new contxt
butane_t butane_init(void) {
  struct butane_ctx *ctx = malloc(sizeof(struct butane_ctx));
  if (!ctx)
    return NULL;

  memset(ctx, 0, sizeof(struct butane_ctx));

  // lock sensitive mem
#if defined(_WIN32)
  if (VirtualLock(ctx, sizeof(struct butane_ctx))) {
#else
  if (mlock(ctx, sizeof(struct butane_ctx)) == 0) {
#endif
    ctx->memory_locked = 1;
  } else {
    ctx->memory_locked = 0;
  }

  // detect hardware aes-ni at session start
  if (butane_cpu_has_aesni())
    ctx->cipher_mode = BUTANE_CIPHER_AES256GCM;
  else
    ctx->cipher_mode = BUTANE_CIPHER_XCHACHA20;

  ctx->flags = BUTANE_FLAG_INITIALIZED;
  return ctx;
}

// find which cipher is active
int butane_get_cipher_mode(butane_t ctx) {
  if (!ctx)
    return 0;
  return ctx->cipher_mode;
}

// free contxt and wipe important stuff
void butane_free(butane_t ctx) {
  if (!ctx)
    return;

  butane_clean(ctx->master_key, BUTANE_KEY_SIZE);
  butane_clean(ctx->salt, BUTANE_SALT_SIZE);
  ctx->flags = 0;
  ctx->cipher_mode = 0;

  // unlock if successfully locked
  if (ctx->memory_locked)
#if defined(_WIN32)
    VirtualUnlock(ctx, sizeof(struct butane_ctx));
#else
    munlock(ctx, sizeof(struct butane_ctx));
#endif

  butane_clean(ctx, sizeof(struct butane_ctx));
  free(ctx);
}
