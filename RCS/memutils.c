#include "memutils.h"

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	include "intrinsics.h"
#endif
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <malloc.h>
#else
#	include <stdlib.h>
#endif

void qsc_memutils_prefetch_l1(uint8_t* address, size_t length)
{
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
	_mm_prefetch(((char*)address + length), _MM_HINT_T0);
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
	_mm_prefetch(((char*)address + length), _MM_HINT_T1);
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
	_mm_prefetch(((char*)address + length), _MM_HINT_T2);
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

void* qsc_memutils_malloc(size_t length)
{
	void* ret;

	ret = NULL;

	if (length != 0)
	{
#if defined(QSC_SYSTEM_COMPILER_MSC)
		ret = _aligned_malloc(length, QSC_SIMD_ALIGNMENT);
#else
		ret = malloc(length);
#endif
	}

	return ret;
}

void* qsc_memutils_realloc(void* block, size_t length)
{
	void* ret;

	ret = NULL;

	if (length != 0)
	{
#if defined(QSC_SYSTEM_COMPILER_MSC)
		ret = _aligned_realloc(block, length, QSC_SIMD_ALIGNMENT);
#else
		ret = realloc(block, length);
#endif
	}

	return ret;
}

void qsc_memutils_alloc_free(void* block)
{
	if (block != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_aligned_free(block);
#else
		free(block);
#endif
	}
}

void* qsc_memutils_aligned_alloc(int32_t align, size_t length)
{
	void* ret;

	ret = NULL;

	if (length != 0)
	{
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_OS_WINDOWS)
		ret = _aligned_malloc(length, align);
#	elif defined(QSC_SYSTEM_OS_POSIX)
		int res;

		res = posix_memalign(&ret, align, length);

		if (res != 0)
		{
			ret = NULL;
		}
#	else
		ret = (void*)malloc(length);
#	endif
#else
		ret = (void*)malloc(length);
#endif
	}

	return ret;
}

void qsc_memutils_aligned_free(void* block)
{
	if (block != NULL)
	{
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_OS_WINDOWS)
		_aligned_free(block);
#	else
		free(block);
#	endif
#else
		free(block);
#endif
	}
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void qsc_memutils_clear128(void* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_setzero_si128());
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void qsc_memutils_clear256(void* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_setzero_si256());
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void qsc_memutils_clear512(void* output)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_setzero_si512());
}
#endif

void qsc_memutils_clear(void* output, size_t length)
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
				qsc_memutils_clear512(((uint8_t*)output + pctr));
#	elif defined(QSC_SYSTEM_HAS_AVX2)
				qsc_memutils_clear256(((uint8_t*)output + pctr));
#	elif defined(QSC_SYSTEM_HAS_AVX)
				qsc_memutils_clear128(((uint8_t*)output + pctr));
#	endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			qsc_memutils_clear256(((uint8_t*)output + pctr));
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			qsc_memutils_clear128(((uint8_t*)output + pctr));
			pctr += 16;
		}
#elif defined(QSC_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			qsc_memutils_clear128(((uint8_t*)output + pctr));
			pctr += 16;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				((uint8_t*)output)[i] = 0x00;
			}
		}
	}
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void qsc_memutils_copy128(const void* input, void* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_loadu_si128((const __m128i*)input));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void qsc_memutils_copy256(const void* input, void* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_loadu_si256((const __m256i*)input));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void qsc_memutils_copy512(const void* input, void* output)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_loadu_si512((const __m512i*)input));
}
#endif

void qsc_memutils_copy(void* output, const void* input, size_t length)
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
				qsc_memutils_copy512((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX2)
				qsc_memutils_copy256((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX)
				qsc_memutils_copy128((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			qsc_memutils_copy256((uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			qsc_memutils_copy128((uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 16;
		}
#elif defined(QSC_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			qsc_memutils_copy128((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 16;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				((uint8_t*)output)[i] = ((const uint8_t*)input)[i];
			}
		}
	}
}

void qsc_memutils_move(void* output, const void* input, size_t length)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	memmove_s(output, length, input, length);
#else
	memmove(output, input, length);
#endif
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void qsc_memutils_setval128(void* output, uint8_t value)
{
	_mm_storeu_si128((__m128i*)output, _mm_set1_epi8(value));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void qsc_memutils_setval256(void* output, uint8_t value)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_set1_epi8(value));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void qsc_memutils_setval512(void* output, uint8_t value)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_set1_epi8(value));
}
#endif

void qsc_memutils_setvalue(void* output, uint8_t value, size_t length)
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
				qsc_memutils_setval512((uint8_t*)output + pctr, value);
#elif defined(QSC_SYSTEM_HAS_AVX2)
				qsc_memutils_setval256((uint8_t*)output + pctr, value);
#elif defined(QSC_SYSTEM_HAS_AVX)
				qsc_memutils_setval128((uint8_t*)output + pctr, value);
#endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			qsc_memutils_setval256((uint8_t*)output + pctr, value);
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			qsc_memutils_setval128((uint8_t*)output + pctr, value);
			pctr += 16;
		}
#elif defined(QSC_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			qsc_memutils_setval128((uint8_t*)output + pctr, value);
			pctr += 16;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				((uint8_t*)output)[i] = value;
			}
		}
	}
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void qsc_memutils_xor128(const uint8_t* input, uint8_t* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*)input), _mm_loadu_si128((const __m128i*)output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void qsc_memutils_xor256(const uint8_t* input, uint8_t* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)input), _mm256_loadu_si256((const __m256i*)output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void qsc_memutils_xor512(const uint8_t* input, uint8_t* output)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)input), _mm512_loadu_si512((__m512i*)output)));
}
#endif

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
			qsc_memutils_xor512((input + pctr), output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX2)
			qsc_memutils_xor256((input + pctr), output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX)
			qsc_memutils_xor128((input + pctr), output + pctr);
#endif
			pctr += SMDBLK;
		}
	}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
	if (length - pctr >= 32)
	{
		qsc_memutils_xor256((input + pctr), output + pctr);
		pctr += 32;
	}
	else if (length - pctr >= 16)
	{
		qsc_memutils_xor128((input + pctr), output + pctr);
		pctr += 16;
	}
#elif defined(QSC_SYSTEM_HAS_AVX2)
	if (length - pctr >= 16)
	{
		qsc_memutils_xor128((input + pctr), output + pctr);
		pctr += 16;
	}
#endif

	if (pctr != length)
	{
		for (size_t i = pctr; i < length; ++i)
		{
			output[i] ^= input[i];
		}
	}
}

#if defined(QSC_SYSTEM_HAS_AVX512)
inline static void qsc_memutils_xorv512(const uint8_t value, uint8_t* output)
{
	__m512i v = _mm512_set1_epi8(value);
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)&v), _mm512_loadu_si512((__m512i*)output)));
}
#elif defined(QSC_SYSTEM_HAS_AVX2)
inline static void qsc_memutils_xorv256(const uint8_t value, uint8_t* output)
{
	__m256i v = _mm256_set1_epi8(value);
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*) & v), _mm256_loadu_si256((const __m256i*)output)));
}
#elif defined(QSC_SYSTEM_HAS_AVX)
inline static void qsc_memutils_xorv128(const uint8_t value, uint8_t* output)
{
	__m128i v = _mm_set1_epi8(value);
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*) & v), _mm_loadu_si128((const __m128i*)output)));
}
#endif

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
			qsc_memutils_xorv512(value, (output + pctr));
#elif defined(QSC_SYSTEM_HAS_AVX2)
			qsc_memutils_xorv256(value, (output + pctr));
#elif defined(QSC_SYSTEM_HAS_AVX)
			qsc_memutils_xorv128(value, (output + pctr));
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
