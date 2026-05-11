#define _DEFAULT_SOURCE
#include "butane.h"
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

// to: wipe memory without being optimized
void butane_clean(void *ptr, size_t len) {
    if (!ptr || len == 0)
        return;
#if defined(__STDC_LIB_EXT1__)
    memset_s(ptr, len, 0, len);
#elif defined(_WIN32)
    SecureZeroMemory(ptr, len);
#else
    explicit_bzero(ptr, len);
#endif
}
