#ifndef QSC_CPUID_H
#define QSC_CPUID_H

#include "common.h"

#if defined(QSC_SYSTEM_COMPILER_MSC) && defined(QSC_SYSTEM_ARCH_X86_X64)
#	include <intrin.h>
#	pragma intrinsic(__cpuid)
#elif defined(QSC_SYSTEM_COMPILER_GCC)
#	include <cpuid.h>
#	pragma GCC target ("aes")
#include <x86intrin.h>
#endif

QSC_EXPORT_API typedef struct
{
    bool has_aesni;
    bool has_avx;
    bool has_avx2;
    bool has_avx512;
    bool has_pclmul;
    bool has_rdrand;
    bool has_rdtcsp;
} qsc_cpu_features;


/**
* \brief Get a list of supported CPU features
*
* \param features: A qsc_cpu_features structure
* \return Returns true for success, false if CPU is not recognized
*/
QSC_EXPORT_API bool qsc_runtime_features(qsc_cpu_features* const features);

#endif