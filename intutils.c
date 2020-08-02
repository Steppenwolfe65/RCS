#include "intutils.h"

bool are_equal8(const uint8_t* a, const uint8_t* b, size_t length)
{
	bool status;
	size_t i;

	status = true;

	for (i = 0; i < length; ++i)
	{
		if (a[i] != b[i])
		{
			status = false;
			break;
		}
	}

	return status;
}

void be8increment(uint8_t* output, size_t outlen)
{
	size_t i = outlen;

	do
	{
		--i;
		++output[i];
	} while (i != 0 && output[i] == 0);
}

uint16_t be8to16(const uint8_t* input)
{
	return (((uint16_t)input[1]) | 
		(uint16_t)((uint16_t)input[0] << 8U));
}

uint32_t be8to32(const uint8_t* input)
{
	return (uint32_t)(input[3]) |
		(((uint32_t)(input[2])) << 8) |
		(((uint32_t)(input[1])) << 16) |
		(((uint32_t)(input[0])) << 24);
}

uint64_t be8to64(const uint8_t* input)
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

void be16to8(uint8_t* output, uint16_t value)
{
	output[1] = (uint8_t)value & 0xFFU;
	output[0] = (uint8_t)(value >> 8) & 0xFFU;
}

void be32to8(uint8_t* output, uint32_t value)
{
	output[3] = (uint8_t)value & 0xFFU;
	output[2] = (uint8_t)(value >> 8) & 0xFFU;
	output[1] = (uint8_t)(value >> 16) & 0xFFU;
	output[0] = (uint8_t)(value >> 24) & 0xFFU;
}

void be64to8(uint8_t* output, uint64_t value)
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

void clear8(uint8_t* a, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void clear32(uint32_t* a, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void clear64(uint64_t* a, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void cmov(uint8_t* r, const uint8_t* x, size_t length, uint8_t b)
{
	size_t i;

	b = ~b + 1;

	for (i = 0; i < length; i++)
	{
		r[i] ^= (uint8_t)(b & (uint8_t)(x[i] ^ r[i]));
	}
}

void le8increment(uint8_t* output, size_t outlen)
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

uint16_t le8to16(const uint8_t* input)
{
	return (((uint16_t)input[0]) |
		(uint16_t)((uint16_t)input[1] << 8U));
}

uint32_t le8to32(const uint8_t* input)
{
	return ((uint32_t)input[0]) |
		((uint32_t)input[1] << 8) |
		((uint32_t)input[2] << 16) |
		((uint32_t)input[3] << 24);
}

uint64_t le8to64(const uint8_t* input)
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

void le16to8(uint8_t* output, uint16_t value)
{
	output[0] = (uint8_t)value & 0xFFU;
	output[1] = (uint8_t)(value >> 8) & 0xFFU;
}

void le32to8(uint8_t* output, uint32_t value)
{
	output[0] = (uint8_t)value & 0xFFU;
	output[1] = (uint8_t)(value >> 8) & 0xFFU;
	output[2] = (uint8_t)(value >> 16) & 0xFFU;
	output[3] = (uint8_t)(value >> 24) & 0xFFU;
}

void le64to8(uint8_t* output, uint64_t value)
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

size_t maxu(size_t a, size_t b)
{
	return (a > b) ? a : b;
}

size_t minu(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

uint32_t rotl32(uint32_t value, size_t shift)
{
	return (value << shift) | (value >> ((sizeof(uint32_t) * 8) - shift));
}

uint64_t rotl64(uint64_t value, size_t shift)
{
	return (value << shift) | (value >> ((sizeof(uint64_t) * 8) - shift));
}

uint32_t rotr32(uint32_t value, size_t shift)
{
	return (value >> shift) | (value << ((sizeof(uint32_t) * 8) - shift));
}

uint64_t rotr64(uint64_t value, size_t shift)
{
	return (value >> shift) | (value << ((sizeof(uint64_t) * 8) - shift));
}

int32_t verify(const uint8_t* a, const uint8_t* b, size_t length)
{
	size_t i;
	uint16_t d;

	d = 0;

	for (i = 0; i < length; ++i)
	{
		d |= (uint16_t)(a[i] ^ b[i]);
	}

	return (1U & ((d - 1U) >> 8U)) - 1U;
}
