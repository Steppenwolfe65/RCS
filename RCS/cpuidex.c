#include "cpuidex.h"
#include "consoleutils.h"
#include "memutils.h"
#include "stringutils.h"

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

#include <stdio.h>
#if defined(QSC_SYSTEM_OS_WINDOWS) && defined(QSC_SYSTEM_COMPILER_MSC)
#   include <Windows.h>
#	include <intrin.h>
#	pragma intrinsic(__cpuid)
#elif defined(QSC_SYSTEM_COMPILER_GCC) && defined(QSC_SYSTEM_OS_POSIX)
#	if defined(QSC_SYSTEM_OS_APPLE)
#   	include <sys/param.h>
#   	include <sys/sysctl.h>
#		include <sys/types.h>
#	else
#		include <cpuid.h>
#		include <x86intrin.h>
#   	include <unistd.h>
#		include <xsaveintrin.h>
#	endif
#endif

#if defined(QSC_SYSTEM_OS_APPLE) && defined(QSC_SYSTEM_COMPILER_GCC)

static void osx_get_features(qsc_cpuidex_cpu_features* features)
{
	size_t plen;
	uint64_t pval;

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.physicalcpu", &pval, &plen, NULL, 0) == 0)
	{
		features->cpus = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.logicalcpu", &pval, &plen, NULL, 0) == 0)
	{
		features->cores = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.logicalcpu", &pval, &plen, NULL, 0) == 0)
	{
		features->hyperthread = (pval > features->cpus);
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cachelinesize", &pval, &plen, NULL, 0) == 0)
	{
		features->cacheline = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency", &pval, &plen, NULL, 0) == 0)
	{
		features->freqbase = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency_max", &pval, &plen, NULL, 0) == 0)
	{
		features->freqmax = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency_min", &pval, &plen, NULL, 0) == 0)
	{
		features->freqref = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.l1dcachesize", &pval, &plen, NULL, 0) == 0)
	{
		features->l1cache = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cachelinesize", &pval, &plen, NULL, 0) == 0)
	{
		features->cacheline = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.l2cachesize", &pval, &plen, NULL, 0) == 0)
	{
		features->l2cache = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.adx", &pval, &plen, NULL, 0) == 0)
	{
		features->adx = (pval == 1);
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.aes", &pval, &plen, NULL, 0) == 0)
	{
		features->aesni = (pval == 1);
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx1_0", &pval, &plen, NULL, 0) == 0)
	{
		features->avx = (pval == 1);
	}


	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx2_0", &pval, &plen, NULL, 0) == 0)
	{
		features->avx2 = (pval == 1);
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx512f", &pval, &plen, NULL, 0) == 0)
	{
		features->avx512f = (pval == 1);
	}

	features->pcmul = features->avx;

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.rdrand", &pval, &plen, NULL, 0) == 0)
	{
		features->rdrand = (pval == 1);
	}

	features->rdtcsp = features->avx;

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.rdrand", &pval, &plen, NULL, 0) == 0)
	{
		features->rdrand = (pval == 1);
	}

	char vend[1024] = { 0 };
	plen = sizeof(vend);

	if (sysctlbyname("machdep.cpu.brand_string", vend, &plen, NULL, 0) >= 0)
	{
		qsc_memutils_copy(features->vendor, vend, QSC_CPUIDEX_VENDOR_LENGTH - 1);
		qsc_stringutils_to_lowercase(vend);

		if (qsc_stringutils_string_contains(vend, "intel") == true)
		{
			features->cputype = qsc_cpuid_intel;
		}
		else if (qsc_stringutils_string_contains(vend, "amd") == true)
		{
			features->cputype = qsc_cpuid_amd;
		}
		else
		{
			features->cputype = qsc_cpuid_unknown;
		}
	}
}

#else

#define CPUID_EBX_AVX2      	0x00000020UL
#define CPUID_EBX_AVX512F   	0x00010000UL
#define CPUID_EBX_AVX512CD  	(1UL << 28)
#define CPUID_EBX_AVX512PF  	(1UL << 26)
#define CPUID_EBX_AVX512ER  	(1UL << 27)
#define CPUID_EBX_AVX512VL  	(1UL << 31)
#define CPUID_EBX_AVX512BW  	(1UL << 30)
#define CPUID_EBX_AVX512DQ  	(1UL << 17)
#define CPUID_EBX_AVX512IFMA 	(1UL << 21)
#define CPUID_EBX_AVX512VBMI 	(1UL <<  1)
#define CPUID_EBX_BMI1       	(1UL <<  3)
#define CPUID_EBX_BMI2       	(1UL <<  8)
#define CPUID_EBX_ADX        	(1UL << 19)
#define CPUID_EBX_SHA        	(1UL << 29)
#define CPUID_EBX_PREFETCHWT1	(1UL <<  0)
#define CPUID_ECX_SSE3      	0x00000001UL
#define CPUID_ECX_PCLMUL    	0x00000002UL
#define CPUID_ECX_SSSE3     	0x00000200UL
#define CPUID_ECX_SSE41     	0x00080000UL
#define CPUID_ECX_AESNI     	0x02000000UL
#define CPUID_ECX_XSAVE     	0x04000000UL
#define CPUID_ECX_OSXSAVE   	0x08000000UL
#define CPUID_ECX_AVX       	0x10000000UL
#define CPUID_ECX_RDRAND    	0x40000000UL
#define CPUID_EDX_SSE2      	0x04000000UL
#define CPUID_EDX_RDTCSP    	0x0000001BUL
#define CPUID_EDX_HYPER     	0x0000001CUL
#define XCR0_SSE            	0x00000002UL
#define XCR0_AVX            	0x00000004UL
#define XCR0_OPMASK         	0x00000020UL
#define XCR0_ZMM_HI256      	0x00000040UL
#define XCR0_HI16_ZMM       	0x00000080UL

static void cpuid_info(uint32_t info[4], const uint32_t infotype)
{
#if defined(QSC_SYSTEM_COMPILER_MSC)
    __cpuid((int*)info, infotype);
#elif defined(QSC_SYSTEM_COMPILER_GCC)
    __get_cpuid(infotype, &info[0], &info[1], &info[2], &info[3]);
#endif
}

static uint32_t read_bits(uint32_t value, int index, int length)
{
    int mask = ((1L << length) - 1) << index;
    return (value & mask) >> index;
}

static void vendor_name(qsc_cpuidex_cpu_features* features)
{
    uint32_t info[4] = { 0 };

    cpuid_info(info, 0x00000000UL);
    qsc_memutils_clear(features->vendor, QSC_CPUIDEX_VENDOR_LENGTH);
    qsc_memutils_copy(&features->vendor[0], &info[1], sizeof(uint32_t));
    qsc_memutils_copy(&features->vendor[4], &info[3], sizeof(uint32_t));
    qsc_memutils_copy(&features->vendor[8], &info[2], sizeof(uint32_t));
}

static void bus_info(qsc_cpuidex_cpu_features* features)
{
    uint32_t info[4] = { 0 };
    cpuid_info(info, 0x00000000UL);

    if (info[0] >= 0x00000016UL)
    {
        qsc_memutils_clear(info, sizeof(info));
        cpuid_info(info, 0x00000016UL);
        features->freqbase = info[0];
        features->freqmax = info[1];
        features->freqref = info[2];
    }
}

static void cpu_cache(qsc_cpuidex_cpu_features* features)
{
    uint32_t info[4] = { 0 };

    cpuid_info(info, 0x80000006UL);

    features->l1cache = read_bits(info[2], 0, 8);
    features->l1cacheline = read_bits(info[2], 0, 11);
    features->l2associative = read_bits(info[2], 12, 4);
    features->l2cache = read_bits(info[2], 16, 16);
}

static uint32_t cpu_count()
{
    uint32_t count;

#if defined(QSC_SYSTEM_OS_WINDOWS)

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    count = (uint32_t)sysinfo.dwNumberOfProcessors;

#else

    count = sysconf(_SC_NPROCESSORS_ONLN);

#endif

    if (count < 1)
    {
        count = 1;
    }

    return count;
}

static void cpu_topology(qsc_cpuidex_cpu_features* features)
{
    uint32_t info[4] = { 0 };

    /* total cpu cores */
    features->cores = cpu_count();

    /* hyperthreading and actual cpus */
    cpuid_info(info, 0x00000001UL);
    features->hyperthread = read_bits(info[3], 28, 1) != 0;
    features->cpus = (features->hyperthread == true && features->cores > 1) ? (features->cores / 2) : features->cores;

    /* cache line size */
    cpuid_info(info, 0x00000001UL);

    /* cpu features */
    features->pcmul = ((info[2] & CPUID_ECX_PCLMUL) != 0x00000000UL);
    features->aesni = ((info[2] & CPUID_ECX_AESNI) != 0x00000000UL);
    features->rdrand = ((info[2] & CPUID_ECX_RDRAND) != 0x00000000UL);
    features->rdtcsp = ((info[3] & CPUID_EDX_RDTCSP) != 0x00000000UL);

#if defined(QSC_SYSTEM_HAS_AVX)
    bool havx;

    havx = (info[2] & CPUID_ECX_AVX) != 0x00000000UL;

    if (havx == true)
    {
    	uint32_t xcr0;

    	xcr0 = 0;

		if ((info[2] & (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) ==
				(CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE))
		{
			xcr0 = (uint32_t)_xgetbv(0);
		}

		if ((xcr0 & (XCR0_SSE | XCR0_AVX)) == (XCR0_SSE | XCR0_AVX))
		{
			features->avx = true;
		}
    }
#endif

    if (features->cputype == qsc_cpuid_intel)
    {
        features->cacheline = read_bits(info[1], 16, 8) * 8;
    }
    else if (features->cputype == qsc_cpuid_amd)
    {
        cpuid_info(info, 0x80000005UL);
        features->cacheline = read_bits(info[2], 24, 8);
    }

    if (features->avx == true)
    {
#if defined(QSC_SYSTEM_HAS_AVX2)
    	bool havx2;

#	if defined(QSC_SYSTEM_COMPILER_GCC)
		__builtin_cpu_init();
		havx2 = __builtin_cpu_supports("avx2") != 0;
#	else
        qsc_memutils_clear(info, sizeof(info));
        cpuid_info(info, 0x00000007UL);
		havx2 = ((info[1] & CPUID_EBX_AVX2) != 0x00000000UL);
		features->adx = ((info[1] & CPUID_EBX_ADX) != 0x00000000UL);
#	endif

		if (havx2 == true)
		{
			features->avx2 = (_xgetbv(0) & 0xE6) != 0;
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		bool havx512;
#	if defined(QSC_SYSTEM_COMPILER_GCC)
		havx512 = __builtin_cpu_supports("avx512f") != 0;
#	else
		havx512 = ((info[1] & CPUID_EBX_AVX512F) != 0x00000000UL);
#	endif
		if (havx512 == true)
		{
			uint32_t xcr2;

			xcr2 = (uint32_t)_xgetbv(0);

			if ((xcr2 & (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM)) ==
					(XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM))
			{
				features->avx512f = true;
			}
		}
#endif
    }
}

static void cpu_type(qsc_cpuidex_cpu_features* features)
{
    char tmpn[QSC_CPUIDEX_VENDOR_LENGTH + 1] = { 0 };

    vendor_name(features);
    qsc_memutils_copy(tmpn, features->vendor, QSC_CPUIDEX_VENDOR_LENGTH);
    qsc_stringutils_to_lowercase(tmpn);

    if (qsc_stringutils_string_contains(tmpn, "intel") == true)
    {
        features->cputype = qsc_cpuid_intel;
    }
    else if (qsc_stringutils_string_contains(tmpn, "amd") == true)
    {
        features->cputype = qsc_cpuid_amd;
    }
    else
    {
        features->cputype = qsc_cpuid_unknown;
    }
}

static void serial_number(qsc_cpuidex_cpu_features* features)
{
    uint32_t info[4] = { 0 };

    cpuid_info(info, 0x00000003UL);
    qsc_memutils_clear(features->serial, QSC_CPUIDEX_SERIAL_LENGTH);
    qsc_memutils_copy(&features->serial[0], &info[1], sizeof(uint32_t));
    qsc_memutils_copy(&features->serial[4], &info[3], sizeof(uint32_t));
    qsc_memutils_copy(&features->serial[8], &info[2], sizeof(uint32_t));
}

#endif

bool qsc_cpuidex_features_set(qsc_cpuidex_cpu_features* features)
{
    bool res;

    features->adx = false;
    features->aesni = false;
    features->avx = false;
    features->avx2 = false;
    features->avx512f = false;
    features->hyperthread = false;
    features->pcmul = false;
    features->rdrand = false;
    features->rdtcsp = false;
    features->cacheline = 0;
    features->cores = 0;
    features->cpus = 1;
    features->freqbase = 0;
    features->freqmax = 0;
    features->freqref = 0;
    features->l1cache = 0;
    features->l1cacheline = 0;
    features->l2associative = 4;
    features->l2cache = 0;
	res = false;
    qsc_memutils_clear(features->serial, QSC_CPUIDEX_SERIAL_LENGTH);

#if defined(QSC_SYSTEM_OS_APPLE) && defined(QSC_SYSTEM_COMPILER_GCC)
    osx_get_features(features);
    res = true;
#elif defined(QSC_SYSTEM_COMPILER_GCC) || defined(QSC_SYSTEM_OS_WINDOWS)
    cpu_type(features);

    if (features->cputype == qsc_cpuid_intel || features->cputype == qsc_cpuid_amd)
    {
        bus_info(features);
        cpu_cache(features);
        cpu_topology(features);
        serial_number(features);
        res = true;
    }
#endif

    return res;
}

void qsc_cpuidex_print_stats()
{
	qsc_cpuidex_cpu_features cfeat;
	const char sf[] = "false";
	const char st[] = "true";
	char vstr[16] = {0};
	bool hfeat;

	hfeat = qsc_cpuidex_features_set(&cfeat);

	if (hfeat == true)
	{
		qsc_consoleutils_print_safe("ADX: ");
		qsc_consoleutils_print_line(cfeat.adx == true ? st : sf);

		qsc_consoleutils_print_safe("AESNI: ");
		qsc_consoleutils_print_line(cfeat.aesni == true ? st : sf);

		qsc_consoleutils_print_safe("AVX: ");
		qsc_consoleutils_print_line(cfeat.avx == true ? st : sf);

		qsc_consoleutils_print_safe("AVX2: ");
		qsc_consoleutils_print_line(cfeat.avx2 == true ? st : sf);

		qsc_consoleutils_print_safe("AVX512: ");
		qsc_consoleutils_print_line(cfeat.avx512f == true ? st : sf);

		qsc_consoleutils_print_safe("Hyperthread: ");
		qsc_consoleutils_print_line(cfeat.hyperthread == true ? st : sf);

		qsc_consoleutils_print_safe("PCLMULQDQ: ");
		qsc_consoleutils_print_line(cfeat.pcmul == true ? st : sf);

		qsc_consoleutils_print_safe("RDRAND: ");
		qsc_consoleutils_print_line(cfeat.rdrand == true ? st : sf);

		qsc_consoleutils_print_safe("RDTCSP: ");
		qsc_consoleutils_print_line(cfeat.rdtcsp == true ? st : sf);

		qsc_consoleutils_print_safe("Cacheline size: ");
		qsc_stringutils_int_to_string((int32_t)cfeat.cacheline, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("CPUs: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.cpus, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("CPU cores: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.cores, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("Frequency base: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.freqbase, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("Frequency max: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.freqmax, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("Frequency ref: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.freqref, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("L1 cache size: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.l1cache, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("L2 cache size: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.l2cache, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("L2 associative: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.l2associative, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("CPU Vendor: ");
		qsc_consoleutils_print_line(cfeat.vendor);
	}
}
