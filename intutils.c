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
	} 
	while (i != 0 && output[i] == 0);
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

void be32to8(uint8_t* output, uint32_t value)
{
	output[3] = value & 0xFF;
	output[2] = (value >> 8) & 0xFF;
	output[1] = (value >> 16) & 0xFF;
	output[0] = (value >> 24) & 0xFF;
}

void be64to8(uint8_t* output, uint64_t value)
{
	output[7] = value & 0xFF;
	output[6] = (value >> 8) & 0xFF;
	output[5] = (value >> 16) & 0xFF;
	output[4] = (value >> 24) & 0xFF;
	output[3] = (value >> 32) & 0xFF;
	output[2] = (value >> 40) & 0xFF;
	output[1] = (value >> 48) & 0xFF;
	output[0] = (value >> 56) & 0xFF;
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

uint16_t le8to16(const uint8_t* input)
{
	return ((uint16_t)input[0]) |
		((uint16_t)input[1] << 8);
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

void le16to8(uint8_t* output, uint16_t value)
{
	output[0] = value & 0xFF;
	output[1] = (value >> 8) & 0xFF;
}

void le32to8(uint8_t* output, uint32_t value)
{
	output[0] = value & 0xFF;
	output[1] = (value >> 8) & 0xFF;
	output[2] = (value >> 16) & 0xFF;
	output[3] = (value >> 24) & 0xFF;
}

void le64to8(uint8_t* output, uint64_t value)
{
	output[0] = value & 0xFF;
	output[1] = (value >> 8) & 0xFF;
	output[2] = (value >> 16) & 0xFF;
	output[3] = (value >> 24) & 0xFF;
	output[4] = (value >> 32) & 0xFF;
	output[5] = (value >> 40) & 0xFF;
	output[6] = (value >> 48) & 0xFF;
	output[7] = (value >> 56) & 0xFF;
}

uint32_t max(uint32_t a, uint32_t b)
{
	return (a > b) ? a : b;
}

uint32_t min(uint32_t a, uint32_t b)
{
	return (a < b) ? a : b;
}

uint32_t rotl32(uint32_t value, uint32_t shift)
{
	return (value << shift) | (value >> ((sizeof(uint32_t) * 8) - shift));
}

uint64_t rotl64(uint64_t value, uint32_t shift)
{
	return (value << shift) | (value >> ((sizeof(uint64_t) * 8) - shift));
}

uint32_t rotr32(uint32_t value, uint32_t shift)
{
	return (value >> shift) | (value << ((sizeof(uint32_t) * 8) - shift));
}

uint64_t rotr64(uint64_t value, uint32_t shift)
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
		d |= a[i] ^ b[i];
	}

	return (1 & ((d - 1) >> 8)) - 1;
}
