#define _DEFAULT_SOURCE
#include "butane.h"
#include <string.h>

#if defined(__unix__) || defined(__APPLE__)
#include <strings.h>
#endif

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
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(ptr, len);
#else
    // memset fallback
    volatile unsigned char *vptr = (volatile unsigned char *)ptr;
    for (size_t i = 0; i < len; i++) {
        vptr[i] = 0;
    }
#endif
}