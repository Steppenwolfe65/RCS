#include "intutils.h"
#include "memutils.h"

bool qsc_intutils_are_equal8(const uint8_t* a, const uint8_t* b, size_t length)
{
	bool status;

	status = true;

	for (size_t i = 0; i < length; ++i)
	{
		if (a[i] != b[i])
		{
			status = false;
			break;
		}
	}

	return status;
}

void qsc_intutils_be8increment(uint8_t* output, size_t outlen)
{
	size_t i = outlen;

	if (outlen > 0)
	{
		do
		{
			--i;
			++output[i];
		} 
		while (i != 0 && output[i] == 0);
	}
}

uint16_t qsc_intutils_be8to16(const uint8_t* input)
{
	return (((uint16_t)input[1]) | 
		(uint16_t)((uint16_t)input[0] << 8U));
}

uint32_t qsc_intutils_be8to32(const uint8_t* input)
{
	return (uint32_t)(input[3]) |
		(((uint32_t)(input[2])) << 8) |
		(((uint32_t)(input[1])) << 16) |
		(((uint32_t)(input[0])) << 24);
}

uint64_t qsc_intutils_be8to64(const uint8_t* input)
{
	return (uint64_t)(input[7]) |
		(((uint64_t)(input[6])) << 8) |
		(((uint64_t)(input[5])) << 16) |
		(((uint64_t)(input[4])) << 24) |
		(((uint64_t)(input[3])) << 32) |
		(((uint64_t)(input[2])) << 40) |
		(((uint64_t)(input[1])) << 48) |
		(((uint64_t)(input[0])) << 56);
}

void qsc_intutils_be16to8(uint8_t* output, uint16_t value)
{
	output[1] = (uint8_t)value & 0xFFU;
	output[0] = (uint8_t)(value >> 8) & 0xFFU;
}

void qsc_intutils_be32to8(uint8_t* output, uint32_t value)
{
	output[3] = (uint8_t)value & 0xFFU;
	output[2] = (uint8_t)(value >> 8) & 0xFFU;
	output[1] = (uint8_t)(value >> 16) & 0xFFU;
	output[0] = (uint8_t)(value >> 24) & 0xFFU;
}

void qsc_intutils_be64to8(uint8_t* output, uint64_t value)
{
	output[7] = (uint8_t)value & 0xFFU;
	output[6] = (uint8_t)(value >> 8) & 0xFFU;
	output[5] = (uint8_t)(value >> 16) & 0xFFU;
	output[4] = (uint8_t)(value >> 24) & 0xFFU;
	output[3] = (uint8_t)(value >> 32) & 0xFFU;
	output[2] = (uint8_t)(value >> 40) & 0xFFU;
	output[1] = (uint8_t)(value >> 48) & 0xFFU;
	output[0] = (uint8_t)(value >> 56) & 0xFFU;
}

#if defined(QSC_SYSTEM_HAS_AVX)
void qsc_intutils_bswap32(uint32_t* destination, const uint32_t* source, size_t length)
{
	__m128i mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

	for (size_t i = 0; i < length; i += 4)
	{
		_mm_storeu_si128((__m128i*)&destination[i], _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)&source[i]), mask));
	}
}

void qsc_intutils_bswap64(uint64_t* destination, const uint64_t* source, size_t length)
{
	__m128i mask = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);

	for (size_t i = 0; i < length; i += 2)
	{
		_mm_storeu_si128((__m128i*)&destination[i], _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)&source[i]), mask));
	}
}
#endif

void qsc_intutils_clear8(uint8_t* a, size_t count)
{
	for (size_t i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void qsc_intutils_clear16(uint16_t* a, size_t count)
{
	for (size_t i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void qsc_intutils_clear32(uint32_t* a, size_t count)
{
	for (size_t i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void qsc_intutils_clear64(uint64_t* a, size_t count)
{
	for (size_t i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void qsc_intutils_cmov(uint8_t* dest, const uint8_t* source, size_t length, uint8_t cond)
{
	cond = ~cond + 1;

	for (size_t i = 0; i < length; i++)
	{
		dest[i] ^= (uint8_t)(cond & (uint8_t)(source[i] ^ dest[i]));
	}
}

size_t qsc_intutils_expand_mask(size_t x)
{
	size_t r;

	r = x;

	/* fold r down to a single bit */
	for (size_t i = 1; i != sizeof(size_t) * 8; i *= 2)
	{
		r |= r >> i;
	}

	r &= 1;
	r = ~(r - 1);

	return r;
}

bool qsc_intutils_are_equal(size_t x, size_t y)
{
	return (bool)((x ^ y) == 0);
}

bool qsc_intutils_is_gte(size_t x, size_t y)
{
	return (bool)(x >= y);
}

void qsc_intutils_bin_to_hex(const uint8_t* input, char* hexstr, size_t length)
{
	const uint8_t ENCODING_TABLE[16] =
	{
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
	};

	size_t ctr;
	int32_t vct;

	ctr = 0;

	for (size_t i = 0; i < length; ++i)
	{
		vct = input[i];
		hexstr[ctr] = ENCODING_TABLE[vct >> 4];
		++ctr;
		hexstr[ctr] = ENCODING_TABLE[vct & 0x0F];
		++ctr;
	}
}

void qsc_intutils_hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
{
	uint8_t idx0;
	uint8_t idx1;

	const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	qsc_memutils_clear(output, length);

	for (size_t pos = 0; pos < (length * 2); pos += 2)
	{
		idx0 = ((uint8_t)hexstr[pos + 0] & 0x1FU) ^ 0x10U;
		idx1 = ((uint8_t)hexstr[pos + 1] & 0x1FU) ^ 0x10U;
		output[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	}
}

void qsc_intutils_le8increment(uint8_t* output, size_t outlen)
{
	size_t i;

	i = 0;

	while (i < outlen)
	{
		++output[i];

		if (output[i] != 0)
		{
			break;
		}

		++i;
	}
}

#if defined(QSC_SYSTEM_HAS_AVX)
void qsc_intutils_leincrement_x128(__m128i* counter)
{
	*counter = _mm_add_epi64(*counter, _mm_set_epi64x(0, 1));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
void qsc_intutils_leincrement_x512(__m512i* counter)
{
	*counter = _mm512_add_epi64(*counter, _mm512_set_epi64(0, 4, 0, 4, 0, 4, 0, 4));
}
#endif

uint16_t qsc_intutils_le8to16(const uint8_t* input)
{
	return (((uint16_t)input[0]) |
		(uint16_t)((uint16_t)input[1] << 8U));
}

uint32_t qsc_intutils_le8to32(const uint8_t* input)
{
	return ((uint32_t)input[0]) |
		((uint32_t)input[1] << 8) |
		((uint32_t)input[2] << 16) |
		((uint32_t)input[3] << 24);
}

uint64_t qsc_intutils_le8to64(const uint8_t* input)
{
	return ((uint64_t)input[0]) |
		((uint64_t)input[1] << 8) |
		((uint64_t)input[2] << 16) |
		((uint64_t)input[3] << 24) |
		((uint64_t)input[4] << 32) |
		((uint64_t)input[5] << 40) |
		((uint64_t)input[6] << 48) |
		((uint64_t)input[7] << 56);
}

void qsc_intutils_le16to8(uint8_t* output, uint16_t value)
{
	output[0] = (uint8_t)value & 0xFFU;
	output[1] = (uint8_t)(value >> 8) & 0xFFU;
}

void qsc_intutils_le32to8(uint8_t* output, uint32_t value)
{
	output[0] = (uint8_t)value & 0xFFU;
	output[1] = (uint8_t)(value >> 8) & 0xFFU;
	output[2] = (uint8_t)(value >> 16) & 0xFFU;
	output[3] = (uint8_t)(value >> 24) & 0xFFU;
}

void qsc_intutils_le64to8(uint8_t* output, uint64_t value)
{
	output[0] = (uint8_t)value & 0xFFU;
	output[1] = (uint8_t)(value >> 8) & 0xFFU;
	output[2] = (uint8_t)(value >> 16) & 0xFFU;
	output[3] = (uint8_t)(value >> 24) & 0xFFU;
	output[4] = (uint8_t)(value >> 32) & 0xFFU;
	output[5] = (uint8_t)(value >> 40) & 0xFFU;
	output[6] = (uint8_t)(value >> 48) & 0xFFU;
	output[7] = (uint8_t)(value >> 56) & 0xFFU;
}

size_t qsc_intutils_max(size_t a, size_t b)
{
	return (a > b) ? a : b;
}

size_t qsc_intutils_min(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

#if defined(QSC_SYSTEM_HAS_AVX)
void qsc_intutils_reverse_bytes_x128(const __m128i* input, __m128i* output)
{
	__m128i mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

	*output = _mm_shuffle_epi8(*input, mask);
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
void qsc_intutils_reverse_bytes_x512(const __m512i* input, __m512i* output)
{
	__m512i mask = _mm512_set_epi8(
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 
		32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 
		48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63);

	*output = _mm512_shuffle_epi8(*input, mask);
}
#endif

uint32_t qsc_intutils_rotl32(uint32_t value, size_t shift)
{
	return (value << shift) | (value >> ((sizeof(uint32_t) * 8) - shift));
}

uint64_t qsc_intutils_rotl64(uint64_t value, size_t shift)
{
	return (value << shift) | (value >> ((sizeof(uint64_t) * 8) - shift));
}

uint32_t qsc_intutils_rotr32(uint32_t value, size_t shift)
{
	return (value >> shift) | (value << ((sizeof(uint32_t) * 8) - shift));
}

uint64_t qsc_intutils_rotr64(uint64_t value, size_t shift)
{
	return (value >> shift) | (value << ((sizeof(uint64_t) * 8) - shift));
}

int32_t qsc_intutils_verify(const uint8_t* a, const uint8_t* b, size_t length)
{
	uint16_t d;

	d = 0;

	for (size_t i = 0; i < length; ++i)
	{
		d |= (uint16_t)(a[i] ^ b[i]);
	}

	return (1U & ((d - 1U) >> 8U)) - 1U;
}
