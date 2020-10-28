#include "memutils.h"
#include <stdlib.h>

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	include "intrinsics.h"
#endif
#if defined(QSC_SYSTEM_COMPILER_MSC)
#	include <malloc.h>
#endif

void qsc_memutils_prefetch_l1(uint8_t* address, size_t length)
{
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
	_mm_prefetch((char*)(address + length), _MM_HINT_T0);
#else
	volatile uint8_t tmp;
	size_t i;

	tmp = 0;

	for (i = 0; i < length; ++i)
	{
		tmp |= address[i];
	}
#endif
}

void qsc_memutils_prefetch_l2(uint8_t* address, size_t length)
{
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
	_mm_prefetch((char*)(address + length), _MM_HINT_T1);
#else
	volatile uint8_t tmp;
	size_t i;

	tmp = 0;

	for (i = 0; i < length; ++i)
	{
		tmp |= address[i];
	}
#endif
}

void qsc_memutils_prefetch_l3(uint8_t* address, size_t length)
{
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
	_mm_prefetch((char*)(address + length), _MM_HINT_T2);
#else
	volatile uint8_t tmp;
	size_t i;

	tmp = 0;

	for (i = 0; i < length; ++i)
	{
		tmp |= address[i];
	}
#endif
}

uint8_t* qsc_memutils_aligned_alloc(int align, size_t length)
{
	uint8_t* ret;

	ret = NULL;

	if (length != 0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		ret = (uint8_t*)_mm_malloc(length, align);
#elif defined(QSC_SYSTEM_OS_POSIX)
		posix_memalign(&ret, align, length);
#else
		ret = (uint8_t*)malloc(length);
#endif
	}

	return ret;
}

void qsc_memutils_aligned_free(uint8_t* block)
{
	if (block != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_mm_free(block);
#else
		free(block);
#endif
	}
}

inline static void qsc_memutils_clear128(uint8_t* output)
{
#if defined(QSC_SYSTEM_HAS_AVX)
	_mm_storeu_si128((__m128i*)output, _mm_setzero_si128());
#else
	memset(output, 0x00, 16);
#endif
}

inline static void qsc_memutils_clear256(uint8_t* output)
{
#if defined(QSC_SYSTEM_HAS_AVX2)
	_mm256_storeu_si256((__m256i*)output, _mm256_setzero_si256());
#else
	qsc_memutils_clear128((uint8_t*)output);
	qsc_memutils_clear128((uint8_t*)(output + 16));
#endif
}

inline static void qsc_memutils_clear512(uint8_t* output)
{
#if defined(QSC_SYSTEM_HAS_AVX512)
	_mm512_storeu_si512((__m512i*)output, _mm512_setzero_si512());
#else
	qsc_memutils_clear256((uint8_t*)output);
	qsc_memutils_clear256((uint8_t*)(output + 32));
#endif
}

void qsc_memutils_clear(uint8_t* output, size_t length)
{
	size_t pctr;

	if (length != 0)
	{
		pctr = 0;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32;
#	else
		const size_t SMDBLK = 16;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#	if defined(QSC_SYSTEM_HAS_AVX512)
				qsc_memutils_clear512((uint8_t*)(output + pctr));
#	elif defined(QSC_SYSTEM_HAS_AVX2)
				qsc_memutils_clear256((uint8_t*)(output + pctr));
#	elif defined(QSC_SYSTEM_HAS_AVX)
				qsc_memutils_clear128((uint8_t*)(output + pctr));
#	endif
				pctr += SMDBLK;
			}
		}
#endif

		if (pctr != length)
		{
			memset((uint8_t*)(output + pctr), 0x00, length - pctr);
		}
	}
}

inline static void qsc_memutils_copy128(const uint8_t* input, uint8_t* output)
{
#if defined(QSC_SYSTEM_HAS_AVX)
	_mm_storeu_si128((__m128i*)output, _mm_loadu_si128((const __m128i*)input));
#else
	memcpy(output, input, 16);
#endif
}

inline static void qsc_memutils_copy256(const uint8_t* input, uint8_t* output)
{
#if defined(QSC_SYSTEM_HAS_AVX2)
	_mm256_storeu_si256((__m256i*)output, _mm256_loadu_si256((const __m256i*)input));
#else
	qsc_memutils_copy128(input, output);
	qsc_memutils_copy128((uint8_t*)(input + 16), (uint8_t*)(output + 16));
#endif
}

inline static void qsc_memutils_copy512(const uint8_t* input, uint8_t* output)
{
#if defined(QSC_SYSTEM_HAS_AVX512)
	_mm512_storeu_si512((__m512i*)output, _mm512_loadu_si512((const __m512i*)input));
#else
	qsc_memutils_copy256(input, output);
	qsc_memutils_copy256((uint8_t*)(input + 32), (uint8_t*)(output + 32));
#endif
}

void qsc_memutils_copy(uint8_t* output, const uint8_t* input, size_t length)
{
	size_t pctr;

	if (length != 0)
	{
		pctr = 0;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32;
#	else
		const size_t SMDBLK = 16;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#if defined(QSC_SYSTEM_HAS_AVX512)
				qsc_memutils_copy512((uint8_t*)(input + pctr), output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX2)
				qsc_memutils_copy256((uint8_t*)(input + pctr), output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX)
				qsc_memutils_copy128((uint8_t*)(input + pctr), output + pctr);
#endif
				pctr += SMDBLK;
			}
		}
#endif

		if (pctr != length)
		{
			memcpy((uint8_t*)(output + pctr), (uint8_t*)(input + pctr), length - pctr);
		}
	}
}

inline static void qsc_memutils_setval128(uint8_t* output, uint8_t value)
{
#if defined(QSC_SYSTEM_HAS_AVX)
	_mm_storeu_si128((__m128i*)output, _mm_set1_epi8(value));
#else
	memset(output, value, 16);
#endif
}

inline static void qsc_memutils_setval256(uint8_t* output, uint8_t value)
{
#if defined(QSC_SYSTEM_HAS_AVX2)
	_mm256_storeu_si256((__m256i*)output, _mm256_set1_epi8(value));
#else
	qsc_memutils_setval128(output, value);
	qsc_memutils_setval128((uint8_t*)(output + 16), value);
#endif
}

inline static void qsc_memutils_setval512(uint8_t* output, uint8_t value)
{
#if defined(QSC_SYSTEM_HAS_AVX512)
	_mm512_storeu_si512((__m512i*)output, _mm512_set1_epi8(value));
#else
	qsc_memutils_setval256(output, value);
	qsc_memutils_setval256((uint8_t*)(output + 32), value);
#endif
}

void qsc_memutils_setvalue(uint8_t* output, size_t length, uint8_t value)
{
	size_t pctr;

	if (length != 0)
	{
		pctr = 0;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32;
#	else
		const size_t SMDBLK = 16;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#if defined(QSC_SYSTEM_HAS_AVX512)
				qsc_memutils_setval512((uint8_t*)(output + pctr), value);
#elif defined(QSC_SYSTEM_HAS_AVX2)
				qsc_memutils_setval256((uint8_t*)(output + pctr), value);
#elif defined(QSC_SYSTEM_HAS_AVX)
				qsc_memutils_setval128((uint8_t*)(output + pctr), value);
#endif
				pctr += SMDBLK;
			}
		}
#endif

		if (pctr != length)
		{
			memset((uint8_t*)(output + pctr), value, length - pctr);
		}
	}
}

inline static void qsc_memutils_xor128(const uint8_t* input, uint8_t* output)
{
#if defined(QSC_SYSTEM_HAS_AVX)
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*)input), _mm_loadu_si128((__m128i*)output)));
#else
	size_t i;

	for (i = 0; i < 16; ++i)
	{
		output[i] ^= input[i];
	}
#endif
}

inline static void qsc_memutils_xor256(const uint8_t* input, uint8_t* output)
{
#if defined(QSC_SYSTEM_HAS_AVX2)
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)input), _mm256_loadu_si256((__m256i*)output)));
#else
	qsc_memutils_xor128(input, output);
	qsc_memutils_xor128((uint8_t*)(input + 16), (uint8_t*)(output + 16));
#endif
}

inline static void qsc_memutils_xor512(const uint8_t* input, uint8_t* output)
{
#if defined(QSC_SYSTEM_HAS_AVX512)
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)input), _mm512_loadu_si512((__m512i*)output)));
#else
	qsc_memutils_xor256(input, output);
	qsc_memutils_xor256((uint8_t*)(input + 32), (uint8_t*)(output + 32));
#endif
}

void qsc_memutils_xor(uint8_t* output, const uint8_t* input, size_t length)
{
	size_t pctr;

	pctr = 0;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
	const size_t SMDBLK = 64;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
	const size_t SMDBLK = 32;
#	else
	const size_t SMDBLK = 16;
#	endif

	if (length >= SMDBLK)
	{
		const size_t ALNLEN = length - (length % SMDBLK);

		while (pctr != ALNLEN)
		{
#if defined(QSC_SYSTEM_HAS_AVX512)
			qsc_memutils_xor512((uint8_t*)(input + pctr), output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX2)
			qsc_memutils_xor256((uint8_t*)(input + pctr), output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX)
			qsc_memutils_xor128((uint8_t*)(input + pctr), output + pctr);
#endif
			pctr += SMDBLK;
		}
	}
#endif

	if (pctr != length)
	{
		size_t i;

		for (i = pctr; i < length; ++i)
		{
			output[i] ^= input[i];
		}
	}
}

inline static void qsc_memutils_xorv128(const uint8_t value, uint8_t* output)
{
#if defined(QSC_SYSTEM_HAS_AVX)
	__m128i v = _mm_set1_epi8(value);
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*) &v), _mm_loadu_si128((__m128i*)output)));
#else
	for (size_t i = 0; i < 16; ++i)
	{
		output[i] ^= value;
	}
#endif
}

inline static void qsc_memutils_xorv256(const uint8_t value, uint8_t* output)
{
#if defined(QSC_SYSTEM_HAS_AVX2)
	__m256i v = _mm256_set1_epi8(value);
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*) & v), _mm256_loadu_si256((__m256i*)output)));
#else
	qsc_memutils_xorv128(value, output);
	qsc_memutils_xorv128(value, (uint8_t*)(output + 16));
#endif
}

inline static void qsc_memutils_xorv512(const uint8_t value, uint8_t* output)
{
#if defined(QSC_SYSTEM_HAS_AVX512)
	__m512i v = _mm512_set1_epi8(value);
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)&v), _mm512_loadu_si512((__m512i*)output)));
#else
	qsc_memutils_xorv256(value, output);
	qsc_memutils_xorv256(value, (uint8_t*)(output + 32));
#endif
}

void qsc_memutils_xorv(uint8_t* output, const uint8_t value, size_t length)
{
	size_t pctr;

	pctr = 0;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
	const size_t SMDBLK = 64;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
	const size_t SMDBLK = 32;
#	else
	const size_t SMDBLK = 16;
#	endif

	if (length >= SMDBLK)
	{
		const size_t ALNLEN = length - (length % SMDBLK);

		while (pctr != ALNLEN)
		{
#if defined(QSC_SYSTEM_HAS_AVX512)
			qsc_memutils_xorv512(value, (uint8_t*)(output + pctr));
#elif defined(QSC_SYSTEM_HAS_AVX2)
			qsc_memutils_xorv256(value, (uint8_t*)(output + pctr));
#elif defined(QSC_SYSTEM_HAS_AVX)
			qsc_memutils_xorv128(value, (uint8_t*)(output + pctr));
#endif
			pctr += SMDBLK;
		}
	}
#endif

	if (pctr != length)
	{
		for (size_t i = pctr; i < length; ++i)
		{
			output[i] ^= value;
		}
	}
}
