#define _DEFAULT_SOURCE
#include "butane.h"
#include <string.h>

// to: wipe memory without being optimized
void butane_clean(void *ptr, size_t len) {
    if (!ptr || len == 0)
        return;
#if defined(__STDC_LIB_EXT1__)
    memset_s(ptr, len, 0, len);
#else
    explicit_bzero(ptr, len);
#endif
}
