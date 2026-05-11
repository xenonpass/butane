#include "hwdetect.h"

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

// check for hardware aes support
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
