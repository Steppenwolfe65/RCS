#include "cpuid.h"

#define CPUID_EBX_AVX2      0x00000020
#define CPUID_EBX_AVX512F   0x00010000
#define CPUID_ECX_SSE3      0x00000001
#define CPUID_ECX_PCLMUL    0x00000002
#define CPUID_ECX_SSSE3     0x00000200
#define CPUID_ECX_SSE41     0x00080000
#define CPUID_ECX_AESNI     0x02000000
#define CPUID_ECX_XSAVE     0x04000000
#define CPUID_ECX_OSXSAVE   0x08000000
#define CPUID_ECX_AVX       0x10000000
#define CPUID_ECX_RDRAND    0x40000000
#define CPUID_EDX_SSE2      0x04000000
#define CPUID_EDX_RDTCSP    0x0000001B
#define XCR0_SSE            0x00000002
#define XCR0_AVX            0x00000004
#define XCR0_OPMASK         0x00000020
#define XCR0_ZMM_HI256      0x00000040
#define XCR0_HI16_ZMM       0x00000080

static void qsc_cpuid_info(uint32_t info[4], const uint32_t infotype)
{
#if defined(QSC_SYSTEM_COMPILER_MSC)
    __cpuid((int*)info, infotype);
#elif defined(QSC_SYSTEM_COMPILER_GCC)
    __get_cpuid(infotype, &info[0], &info[1], &info[2], &info[3])
#endif
}

bool qsc_runtime_features(qsc_cpu_features* const features)
{
    uint32_t info[4] = { 0 };
    uint32_t xcr0;
    bool res;

    features->has_aesni = false;
    features->has_avx = false;
    features->has_avx2 = false;
    features->has_avx512 = false;
    features->has_pclmul = false;
    features->has_rdrand = false;
    features->has_rdtcsp = false;
    res = true;
    xcr0 = 0;

    qsc_cpuid_info(info, 0x0);

    if (info[0] != 0)
    {
        qsc_cpuid_info(info, 0x00000001);

#if defined(QSC_WMMINTRIN_H)
        features->has_pclmul = ((info[2] & CPUID_ECX_PCLMUL) != 0x0);
        features->has_aesni = ((info[2] & CPUID_ECX_AESNI) != 0x0);
#endif

        features->has_rdrand = ((info[2] & CPUID_ECX_RDRAND) != 0x0);
        features->has_rdtcsp = ((info[3] & CPUID_EDX_RDTCSP) != 0x0);

#if defined(QSC_SYSTEM_HAS_AVX)
        if ((info[2] & (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) == (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE))
        {
            xcr0 = (uint32_t)_xgetbv(0);
        }

        if ((xcr0 & (XCR0_SSE | XCR0_AVX)) == (XCR0_SSE | XCR0_AVX))
        {
            features->has_avx = true;
        }
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
        if (features->has_avx == true)
        {
            uint32_t info7[4] = { 0 };

            qsc_cpuid_info(info7, 0x00000007);
            features->has_avx2 = ((info7[1] & CPUID_EBX_AVX2) != 0x0);
        }
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
        if (features->has_avx2 == true)
        {
            uint32_t info7x[4] = { 0 };

            qsc_cpuid_info(info7x, 0x00000007);

            if ((info7x[1] & CPUID_EBX_AVX512F) == CPUID_EBX_AVX512F && (xcr0 & (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM))
                == (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM))
            {
                features->has_avx512 = true;
            }
        }
#endif
    }
    else
    {
        res = false;
    }

    return res;
}