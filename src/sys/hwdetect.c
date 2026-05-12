#include "hwdetect.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

// check for hardware aes support (intel/amd)
int butane_cpu_has_aesni(void) {
#if defined(_MSC_VER)
    int cpuinfo[4];
    __cpuid(cpuinfo, 1);
    // aes-ni is bit 25 of ecx from cpuid leaf 1
    return (cpuinfo[2] >> 25) & 1;
#else
    unsigned int eax, ebx, ecx, edx;

    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        return 0;

    return (ecx >> 25) & 1;
#endif
}

#else

// fallback for non-x86/x64
int butane_cpu_has_aesni(void) {
    return 0; // force xchacha20 fallback
}

#endif