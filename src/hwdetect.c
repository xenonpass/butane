#include "hwdetect.h"
#include <cpuid.h>

// check for hardware aes support
int butane_cpu_has_aesni(void) {
    unsigned int eax, ebx, ecx, edx;

    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        return 0;

    // aes-ni is bit 25 of ecx from cpuid leaf 1
    return (ecx >> 25) & 1;
}
