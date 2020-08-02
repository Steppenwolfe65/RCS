#include "rcs.h"
#include "intutils.h"
#include "sha3.h"
#ifdef RCS_HMAC_EXTENSION
#	include "sha2.h"
#endif
#include <assert.h>
#include <stdlib.h>

/*!
\def RCS256_ROUND_COUNT
* The number of Rijndael mixing rounds used by RCS-256.
*/
#define RCS256_ROUND_COUNT 22

/*!
\def RCS512_ROUND_COUNT
* The number of Rijndael ming rounds used by RCS-512.
*/
#define RCS512_ROUND_COUNT 30

/*!
\def ROUNDKEY_ELEMENT_SIZE
* The round key element size in bytes.
*/
#ifdef RCS_AESNI_ENABLED
#	define ROUNDKEY_ELEMENT_SIZE 16
#else
#	define ROUNDKEY_ELEMENT_SIZE 4
#	define RHX_PREFETCH_TABLES
#endif

/*!
\def RCS_NONCE_SIZE
* The size byte size of the CTR nonce and CBC initialization vector.
*/
#define RCS_NONCE_SIZE RCS_BLOCK_SIZE

/*!
\def RCS256_ROUNDKEY_SIZE
* The size of the RCS-256 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an rcs_state struct.
*/
#define RCS256_ROUNDKEY_SIZE ((RCS256_ROUND_COUNT + 1) * (RCS_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def RCS512_ROUNDKEY_SIZE
* The size of the RCS-512 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an rcs_state struct.
*/
#define RCS512_ROUNDKEY_SIZE ((RCS512_ROUND_COUNT + 1) * (RCS_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE))

/*!
\def RCS_INFO_LENGTH
* The HBA version information array length.
*/
#define RCS_INFO_LENGTH 16

/*!
\def RCS256_MKEY_LENGTH
* The size of the hba-rhx256 mac key array
*/
#if defined(RCS_HMAC_EXTENSION)
#	define RCS256_MKEY_LENGTH 64
#else
#	define RCS256_MKEY_LENGTH 32
#endif

/*!
\def RCS512_MKEY_LENGTH
* The size of the hba-rhx512 mac key array
*/
#if defined(RCS_HMAC_EXTENSION)
#	define RCS512_MKEY_LENGTH 128
#else
#	define RCS512_MKEY_LENGTH 64
#endif

/*!
\def RCS_NAME_LENGTH
* The HBA implementation specific name array length.
*/
#define RCS_NAME_LENGTH 17

/*!
\def RCS_INFO_DEFLEN
* The size in bytes of the internal default information string.
*/
#define RCS_INFO_DEFLEN 9

/* default info parameter string literals */
#ifdef RCS_SHAKE_EXTENSION
/* RCS256 */
static const uint8_t RCS_CSHAKE256_INFO[7] = { 82, 72, 88, 83, 50, 53, 54 };
/* RCS512 */
static const uint8_t RCS_CSHAKE512_INFO[7] = { 82, 72, 88, 83, 53, 49, 50 };
#else
/* RHXH256 */
static const uint8_t RCS_HKDF256_INFO[7] = { 82, 72, 88, 72, 50, 53, 54 };
/* RHXH512 */
static const uint8_t RCS_HKDF512_INFO[7] = { 82, 72, 88, 72, 53, 49, 50 };
#endif

#ifdef RCS_HMAC_EXTENSION
	static const uint8_t rcs256_name[RCS_NAME_LENGTH] =
	{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x52, 0x43, 0x53, 0x48, 0x32, 0x35,
		0x36
	};
#else
	static const uint8_t rcs256_name[RCS_NAME_LENGTH] =
	{
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x52, 0x43, 0x53, 0x4B, 0x32, 0x35,
		0x36
	};
#endif

#ifdef RCS_HMAC_EXTENSION
static const uint8_t rcs512_name[RCS_NAME_LENGTH] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x52, 0x43, 0x53, 0x48, 0x35, 0x31,
	0x32
};
#else
static const uint8_t rcs512_name[RCS_NAME_LENGTH] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x52, 0x43, 0x53, 0x4B, 0x35, 0x31,
	0x32
};
#endif

/* aes-ni and table-based fallback functions */

#ifdef RCS_AESNI_ENABLED

static void rcs_encrypt_block(rcs_state* state, __m128i output[2], const __m128i input[2])
{
	const __m128i BLEND_MASK = _mm_set_epi32(0x80000000UL, 0x80800000UL, 0x80800000UL, 0x80808000UL);
	const __m128i SHIFT_MASK = { 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3 };
	const size_t HLFBLK = RCS_BLOCK_SIZE / 2;
	const size_t RNDCNT = state->roundkeylen - 3;
	size_t kctr;

	__m128i blk1 = _mm_loadu_si128(&input[0]);
	__m128i blk2 = _mm_loadu_si128(&input[1]);
	__m128i tmp1;
	__m128i tmp2;

	kctr = 0;
	blk1 = _mm_xor_si128(blk1, state->roundkeys[kctr]);
	++kctr;
	blk2 = _mm_xor_si128(blk2, state->roundkeys[kctr]);

	while (kctr != RNDCNT)
	{
		/* mix the blocks */
		tmp1 = _mm_blendv_epi8(blk1, blk2, BLEND_MASK);
		tmp2 = _mm_blendv_epi8(blk2, blk1, BLEND_MASK);
		/* shuffle */
		tmp1 = _mm_shuffle_epi8(tmp1, SHIFT_MASK);
		tmp2 = _mm_shuffle_epi8(tmp2, SHIFT_MASK);
		++kctr;
		/* encrypt the first half-block */
		blk1 = _mm_aesenc_si128(tmp1, state->roundkeys[kctr]);
		++kctr;
		/* encrypt the second half-block */
		blk2 = _mm_aesenc_si128(tmp2, state->roundkeys[kctr]);
	}

	/* final block */
	tmp1 = _mm_blendv_epi8(blk1, blk2, BLEND_MASK);
	tmp2 = _mm_blendv_epi8(blk2, blk1, BLEND_MASK);
	tmp1 = _mm_shuffle_epi8(tmp1, SHIFT_MASK);
	tmp2 = _mm_shuffle_epi8(tmp2, SHIFT_MASK);
	++kctr;
	blk1 = _mm_aesenclast_si128(tmp1, state->roundkeys[kctr]);
	++kctr;
	blk2 = _mm_aesenclast_si128(tmp2, state->roundkeys[kctr]);

	/* store in output */
	_mm_storeu_si128(&output[0], blk1);
	_mm_storeu_si128(&output[1], blk2);
}

static void rcs_ctr_transform(rcs_state* state, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(state != (rcs_state*)0);
	assert(input != (uint8_t*)0);
	assert(output != (uint8_t*)0);

	const size_t HLFBLK = RCS_BLOCK_SIZE / 2;
	size_t i;
	size_t poff;

	poff = 0;

	while (inputlen >= RCS_BLOCK_SIZE)
	{
		__m128i tmpn[2] = { _mm_loadu_si128((const __m128i*)state->nonce), _mm_loadu_si128((const __m128i*)(state->nonce + HLFBLK)) };
		__m128i tmpo[2] = { 0 };

		rcs_encrypt_block(state, tmpo, tmpn);

		__m128i tmpi[2] = { _mm_loadu_si128((const __m128i*)(input + poff)) , _mm_loadu_si128((const __m128i*)(input + HLFBLK + poff)) };

		tmpo[0] = _mm_xor_si128(tmpo[0], tmpi[0]);
		tmpo[1] = _mm_xor_si128(tmpo[1], tmpi[1]);

		le8increment(state->nonce, RCS_BLOCK_SIZE);

		/* store in output */
		_mm_storeu_si128((__m128i*)(output + poff), tmpo[0]);
		_mm_storeu_si128((__m128i*)(output + HLFBLK + poff), tmpo[1]);

		inputlen -= RCS_BLOCK_SIZE;
		poff += RCS_BLOCK_SIZE;
	}

	if (inputlen != 0)
	{
		__m128i tmpn[2] = { _mm_loadu_si128((const __m128i*)state->nonce), _mm_loadu_si128((const __m128i*)(state->nonce + HLFBLK)) };
		__m128i tmpo[2] = { 0 };
		uint8_t tmpb[RCS_BLOCK_SIZE] = { 0 };

		rcs_encrypt_block(state, tmpo, tmpn);

		/* store in tmp */
		_mm_storeu_si128((__m128i*)tmpb, tmpo[0]);
		_mm_storeu_si128((__m128i*)(tmpb + HLFBLK), tmpo[1]);

		for (i = 0; i < inputlen; ++i)
		{
			output[poff + i] = tmpb[i] ^ input[poff + i];
		}

		le8increment(state->nonce, RCS_BLOCK_SIZE);
	}
}

#else

/* rijndael rcon, and s-box constant tables */

static const uint8_t s_box[256] =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static const uint8_t is_box[256] =
{
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

static const uint32_t rcon[30] =
{
	0x00000000UL, 0x01000000UL, 0x02000000UL, 0x04000000UL, 0x08000000UL, 0x10000000UL, 0x20000000UL, 0x40000000UL,
	0x80000000UL, 0x1B000000UL, 0x36000000UL, 0x6C000000UL, 0xD8000000UL, 0xAB000000UL, 0x4D000000UL, 0x9A000000UL,
	0x2F000000UL, 0x5E000000UL, 0xBC000000UL, 0x63000000UL, 0xC6000000UL, 0x97000000UL, 0x35000000UL, 0x6A000000UL,
	0xD4000000UL, 0xB3000000UL, 0x7D000000UL, 0xFA000000UL, 0xEF000000UL, 0xC5000000UL
};

static void rcs_add_roundkey(uint8_t* state, const uint32_t *skeys)
{
	size_t i;
	uint32_t k;

	for (i = 0; i < RCS_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		k = *skeys;
		state[i] ^= (uint8_t)(k >> 24);
		state[i + 1] ^= (uint8_t)(k >> 16) & 0xFFU;
		state[i + 2] ^= (uint8_t)(k >> 8) & 0xFFU;
		state[i + 3] ^= (uint8_t)k & 0xFFU;
		++skeys;
	}
}

static uint8_t rcs_gf256_reduce(uint32_t x)
{
	uint32_t y;

	y = x >> 8;

	return (x ^ y ^ (y << 1) ^ (y << 3) ^ (y << 4)) & 0xFFU;
}

static void rcs_mix_columns(uint8_t* state)
{
	size_t i;
	uint32_t s0;
	uint32_t s1;
	uint32_t s2;
	uint32_t s3;
	uint32_t t0;
	uint32_t t1;
	uint32_t t2;
	uint32_t t3;

	for (i = 0; i < RCS_BLOCK_SIZE; i += sizeof(uint32_t))
	{
		s0 = state[i + 0];
		s1 = state[i + 1];
		s2 = state[i + 2];
		s3 = state[i + 3];

		t0 = (s0 << 1) ^ s1 ^ (s1 << 1) ^ s2 ^ s3;
		t1 = s0 ^ (s1 << 1) ^ s2 ^ (s2 << 1) ^ s3;
		t2 = s0 ^ s1 ^ (s2 << 1) ^ s3 ^ (s3 << 1);
		t3 = s0 ^ (s0 << 1) ^ s1 ^ s2 ^ (s3 << 1);

		state[i + 0] = (uint8_t)(t0 ^ ((~(t0 >> 8) + 1) & 0x0000011BUL));
		state[i + 1] = (uint8_t)(t1 ^ ((~(t1 >> 8) + 1) & 0x0000011BUL));
		state[i + 2] = (uint8_t)(t2 ^ ((~(t2 >> 8) + 1) & 0x0000011BUL));
		state[i + 3] = (uint8_t)(t3 ^ ((~(t3 >> 8) + 1) & 0x0000011BUL));
	}
}

static void rcs_prefetch_sbox(bool encryption)
{
	size_t i;
	volatile uint32_t dmy;

	dmy = 0;

	if (encryption)
	{
		for (i = 0; i < 256; ++i)
		{
			dmy |= s_box[i];
		}
	}
	else
	{
		for (i = 0; i < 256; ++i)
		{
			dmy |= is_box[i];
		}
	}
}

static void rcs_shift_rows(uint8_t* state)
{
	uint8_t tmp;

	tmp = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = state[17];
	state[17] = state[21];
	state[21] = state[25];
	state[25] = state[29];
	state[29] = tmp;

	tmp = state[2];
	state[2] = state[14];
	state[14] = state[26];
	state[26] = state[6];
	state[6] = state[18];
	state[18] = state[30];
	state[30] = state[10];
	state[10] = state[22];
	state[22] = tmp;

	tmp = state[3];
	state[3] = state[19];
	state[19] = tmp;

	tmp = state[7];
	state[7] = state[23];
	state[23] = tmp;

	tmp = state[11];
	state[11] = state[27];
	state[27] = tmp;

	tmp = state[15];
	state[15] = state[31];
	state[31] = tmp;
}

static void rcs_sub_bytes(uint8_t* state, const uint8_t* sbox)
{
	size_t i;

	for (i = 0; i < RCS_BLOCK_SIZE; ++i)
	{
		state[i] = sbox[state[i]];
	}
}

static uint32_t rcs_substitution(uint32_t rot)
{
	uint32_t val;
	uint32_t res;

	val = rot & 0xFFU;
	res = s_box[val];
	val = (rot >> 8) & 0xFFU;
	res |= ((uint32_t)s_box[val] << 8);
	val = (rot >> 16) & 0xFFU;
	res |= ((uint32_t)s_box[val] << 16);
	val = (rot >> 24) & 0xFFU;

	return res | ((uint32_t)(s_box[val]) << 24);
}

static void rcs_encrypt_block(rcs_state* state, uint8_t* output, const uint8_t* input)
{
	uint8_t buf[RCS_BLOCK_SIZE];
	size_t i;

	memcpy(buf, input, RCS_BLOCK_SIZE);
	rcs_add_roundkey(buf, state->roundkeys);
	rcs_prefetch_sbox(true);

	for (i = 1; i < state->rounds; ++i)
	{
		rcs_sub_bytes(buf, s_box);
		rcs_shift_rows(buf);
		rcs_mix_columns(buf);
		rcs_add_roundkey(buf, state->roundkeys + (i << 3));
	}

	rcs_sub_bytes(buf, s_box);
	rcs_shift_rows(buf);
	rcs_add_roundkey(buf, state->roundkeys + (state->rounds << 3));
	memcpy(output, buf, RCS_BLOCK_SIZE);
}

static void rcs_ctr_transform(rcs_state* state, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	assert(state != (rcs_state*)0);
	assert(input != (uint8_t*)0);
	assert(output != (uint8_t*)0);

	size_t i;
	size_t poff;

	poff = 0;

	while (inputlen >= RCS_BLOCK_SIZE)
	{
		rcs_encrypt_block(state, output + poff, state->nonce);

		for (i = 0; i < RCS_BLOCK_SIZE; ++i)
		{
			output[poff + i] ^= input[poff + i];
		}

		le8increment(state->nonce, RCS_BLOCK_SIZE);

		inputlen -= RCS_BLOCK_SIZE;
		poff += RCS_BLOCK_SIZE;
	}

	if (inputlen != 0)
	{
		uint8_t tmpb[RCS_BLOCK_SIZE] = { 0 };

		rcs_encrypt_block(state, tmpb, state->nonce);

		for (i = 0; i < inputlen; ++i)
		{
			output[poff + i] = tmpb[i] ^ input[poff + i];
		}

		le8increment(state->nonce, RCS_BLOCK_SIZE);
	}
}

#endif

static bool rcs_finalize(rcs_state* state, uint8_t* output, const uint8_t* input, size_t inputlen, uint8_t* ncopy)
{
	uint8_t* minp;
	uint64_t mctr;
	const size_t TLEN = RCS_BLOCK_SIZE + inputlen + state->aadlen + sizeof(uint64_t);
	bool res;

	res = false;
	mctr = 0;

	/* allocate the input array */
	minp = (uint8_t*)malloc(TLEN);

	if (minp != (uint8_t*)0)
	{
		memset(minp, 0x00, TLEN);
		memcpy(minp, ncopy, RCS_BLOCK_SIZE);

		/* copy the ciphertext, aad, and mac counter to the buffer array */
		if (inputlen != 0)
		{
			memcpy(minp + RCS_BLOCK_SIZE, input, inputlen);
		}

		if (state->aadlen != 0)
		{
			memcpy(minp + RCS_BLOCK_SIZE + inputlen, state->aad, state->aadlen);

			/* additional data is cleared after every finalization call */
			memset(state->aad, 0x00, state->aadlen);
			state->aadlen = 0;
		}

		/* add the nonce, input, and aad sizes to the counter */
		mctr = RCS_BLOCK_SIZE + state->counter + state->aadlen + sizeof(uint64_t);
		/* append the counter to the end of the mac input array */
		le64to8(minp + RCS_BLOCK_SIZE + inputlen + state->aadlen, mctr);

		if (state->ctype == RCS256)
		{
#ifdef RCS_HMAC_EXTENSION
			/* mac the data and add the code to the end of the cipher-text output array */
			hmac256_compute(output, minp, TLEN, state->mkey, state->mkeylen);
#else
			/* mac the data and add the code to the end of the cipher-text output array */
			kmac256(output, RCS256_MAC_LENGTH, minp, TLEN, state->mkey, state->mkeylen, NULL, 0);
#endif
		}
		else
		{
#ifdef RCS_HMAC_EXTENSION
			/* mac the data and add the code to the end of the cipher-text output array */
			hmac512_compute(output, minp, TLEN, state->mkey, state->mkeylen);
#else
			/* mac the data and add the code to the end of the cipher-text output array */
			kmac512(output, RCS512_MAC_LENGTH, minp, TLEN, state->mkey, state->mkeylen, NULL, 0);
#endif
		}

		clear8(minp, TLEN);
		free(minp);

		/* generate the new mac key */
		if (state->ctype == RCS256)
		{
			/* generate the new mac key */
			uint8_t tmpn[RCS_NAME_LENGTH] = { 0 };
			uint8_t tmpk[RCS256_MKEY_LENGTH] = { 0 };

			memcpy(tmpn, rcs256_name, RCS_NAME_LENGTH);
			/* add 1 + the nonce, and last input size */
			/* append the counter to the end of the mac input array */
			le64to8(tmpn, state->counter);

			/* generate the key and copy to state */
			cshake256(tmpk, RCS256_MKEY_LENGTH, state->mkey, state->mkeylen, tmpn, RCS_NAME_LENGTH, state->custom, state->custlen);
			memcpy(state->mkey, tmpk, sizeof(tmpk));
		}
		else
		{
			uint8_t tmpn[RCS_NAME_LENGTH] = { 0 };
			uint8_t tmpk[RCS512_MKEY_LENGTH] = { 0 };

			memcpy(tmpn, rcs512_name, RCS_NAME_LENGTH);
			le64to8(tmpn, state->counter);

			cshake512(tmpk, RCS512_MKEY_LENGTH, state->mkey, state->mkeylen, tmpn, RCS_NAME_LENGTH, state->custom, state->custlen);
			memcpy(state->mkey, tmpk, sizeof(tmpk));
		}

		res = true;
	}

	return res;
}

static void rcs_secure_expand(rcs_state* state, const rcs_keyparams* keyparams)
{
	uint8_t sbuf[SHAKE_STATE_SIZE * sizeof(uint64_t)] = { 0 };
	keccak_state kstate;
	size_t i;
	size_t oft;
	size_t rlen;

	clear64(kstate.state, SHAKE_STATE_SIZE);

	if (state->ctype == RCS256)
	{
		uint8_t tmpr[RCS256_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE] = { 0 };

		/* initialize an instance of cSHAKE */
		cshake256_initialize(&kstate, keyparams->key, keyparams->keylen, rcs256_name, RCS_NAME_LENGTH, state->custom, state->custlen);

		oft = 0;
		rlen = RCS256_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE;

		while (rlen != 0)
		{
			const size_t BLKLEN = (rlen > SHAKE_256_RATE) ? SHAKE_256_RATE : rlen;
			cshake256_squeezeblocks(&kstate, sbuf, 1);
			memcpy(tmpr + oft, sbuf, BLKLEN);

			oft += BLKLEN;
			rlen -= BLKLEN;
		}

#ifdef RCS_AESNI_ENABLED
		const size_t RNKLEN = (RCS_BLOCK_SIZE / sizeof(__m128i)) * (state->rounds + 1);

		/* copy p-rand bytes to round keys */
		for (i = 0; i < RNKLEN; ++i)
		{
			state->roundkeys[i] = _mm_loadu_si128((const __m128i*)(tmpr + (i * sizeof(__m128i))));
		}

#else
		/* realign in big endian format for ACS test vectors; RCS is the fallback to the AES-NI implementation */
		for (i = 0; i < RCS256_ROUNDKEY_SIZE; ++i)
		{
			state->roundkeys[i] = be8to32(tmpr + (i * sizeof(uint32_t)));
		}
#endif

		/* use two permutation calls to seperate the cipher/mac key outputs to match the CEX implementation */
		cshake256_squeezeblocks(&kstate, sbuf, 1);
		memcpy(state->mkey, sbuf, RCS256_MKEY_LENGTH);
		/* clear the shake buffer */
		clear64(kstate.state, SHAKE_STATE_SIZE);
	}
	else
	{
		uint8_t tmpr[RCS512_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE] = { 0 };

		/* initialize an instance of cSHAKE */
		cshake512_initialize(&kstate, keyparams->key, keyparams->keylen, rcs512_name, RCS_NAME_LENGTH, state->custom, state->custlen);

		oft = 0;
		rlen = RCS512_ROUNDKEY_SIZE * ROUNDKEY_ELEMENT_SIZE;

		while (rlen != 0)
		{
			const size_t BLKLEN = (rlen > SHAKE_512_RATE) ? SHAKE_512_RATE : rlen;
			cshake512_squeezeblocks(&kstate, sbuf, 1);
			memcpy(tmpr + oft, sbuf, BLKLEN);

			oft += BLKLEN;
			rlen -= BLKLEN;
		}

#ifdef RCS_AESNI_ENABLED
		memcpy((uint8_t*)state->roundkeys, tmpr, sizeof(tmpr));
#else
		/* realign in big endian format for ACS test vectors; RCS is the fallback to the AES-NI implementation */
		for (i = 0; i < RCS512_ROUNDKEY_SIZE; ++i)
		{
			state->roundkeys[i] = be8to32(tmpr + (i * sizeof(uint32_t)));
		}
#endif

		/* use two permutation calls (no buffering) to seperate the cipher/mac key outputs to match the CEX implementation */
		rlen = RCS512_MKEY_LENGTH;
		oft = 0;

		while (rlen != 0)
		{
			const size_t BLKLEN = (rlen > SHAKE_512_RATE) ? SHAKE_512_RATE : rlen;
			cshake512_squeezeblocks(&kstate, sbuf, 1);
			memcpy(state->mkey + oft, sbuf, BLKLEN);

			oft += BLKLEN;
			rlen -= BLKLEN;
		}

		/* clear the shake buffer */
		clear64(kstate.state, SHAKE_STATE_SIZE);
	}
}

/* rcs common */

void rcs_dispose(rcs_state* state)
{
	if (state != (rcs_state*)0)
	{
		memset(state->roundkeys, 0x00, sizeof(state->roundkeys));
		memset(state->mkey, 0x00, sizeof(state->mkey));
		state->aadlen = 0;
		state->counter = 0;
		state->ctype = RCS256;
		state->mkeylen = 0;
		state->roundkeylen = 0;
		state->rounds = 0;
		state->encrypt = false;
	}
}

void rcs_initialize(rcs_state* state, const rcs_keyparams* keyparams, bool encryption, rcs_cipher_type ctype)
{
	state->ctype = ctype;
	memset(state->roundkeys, 0x00, sizeof(state->roundkeys));
	memset(state->mkey, 0x00, sizeof(state->mkey));
	state->nonce = keyparams->nonce;
	state->counter = 1;
	state->encrypt = encryption;
	state->aadlen = 0;
	state->custom = keyparams->info;
	state->custlen = keyparams->infolen;

	if (state->ctype == RCS256)
	{
		/* initialize rcs state */
		state->roundkeylen = RCS256_ROUNDKEY_SIZE;
		state->rounds = 22;
		state->mkeylen = RCS256_MKEY_LENGTH;
	}
	else
	{
		/* initialize rcs state */
		state->roundkeylen = RCS512_ROUNDKEY_SIZE;
		state->rounds = 30;
		state->mkeylen = RCS512_MKEY_LENGTH;
	}

	/* generate the cipher and mac keys */
	rcs_secure_expand(state, keyparams);
}

void rcs_set_associated(rcs_state* state, uint8_t* data, size_t datalen)
{
	state->aad = data;
	state->aadlen = datalen;
}

bool rcs_transform(rcs_state* state, uint8_t* output, const uint8_t* input, size_t inputlen)
{
	uint8_t ncopy[RCS_BLOCK_SIZE] = { 0 };
	bool res;

	res = false;
	/* store the nonce */
	memcpy(ncopy, state->nonce, RCS_BLOCK_SIZE);
	/* update the processed bytes counter */
	state->counter += inputlen;

	if (state->encrypt)
	{
		/* use rhx counter-mode to encrypt the array */
		rcs_ctr_transform(state, output, input, inputlen);

		/* mac the cipher-text appending the code to the end of the array */
		res = rcs_finalize(state, output + inputlen, output, inputlen, ncopy);
	}
	else
	{
		if (state->ctype == RCS256)
		{
			uint8_t code[RCS256_MAC_LENGTH] = { 0 };

			if (rcs_finalize(state, code, input, inputlen, ncopy))
			{
				/* test the mac for equality, bypassing the transform if the mac check fails */
				if (verify(code, input + inputlen, RCS256_MAC_LENGTH) == 0)
				{
					/* use rhx counter-mode to decrypt the array */
					rcs_ctr_transform(state, output, input, inputlen);
					res = true;
				}
			}
		}
		else
		{
			uint8_t code[RCS512_MAC_LENGTH] = { 0 };

			if (rcs_finalize(state, code, input, inputlen, ncopy))
			{
				/* test the mac for equality, bypassing the transform if the mac check fails */
				if (verify(code, input + inputlen, RCS512_MAC_LENGTH) == 0)
				{
					/* use rhx counter-mode to decrypt the array */
					rcs_ctr_transform(state, output, input, inputlen);
					res = true;
				}
			}
		}
	}

	return res;
}