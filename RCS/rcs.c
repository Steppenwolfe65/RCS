#include "rcs.h"
#include "intutils.h"
#include "memutils.h"
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
\def RCS_ROUNDKEY_ELEMENT_SIZE
* The round key element size in bytes.
*/
#ifdef QSC_RCS_AESNI_ENABLED
#	define RCS_ROUNDKEY_ELEMENT_SIZE 16
#	define RCS_AVX512_BLOCK 64
#else
#	define RCS_ROUNDKEY_ELEMENT_SIZE 4
#	define RCS_PREFETCH_TABLES
#endif

/*!
\def RCS256_ROUNDKEY_SIZE
* The size of the RCS-256 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_rcs_state struct.
*/
#define RCS256_ROUNDKEY_SIZE ((RCS256_ROUND_COUNT + 1) * (QSC_RCS_BLOCK_SIZE / RCS_ROUNDKEY_ELEMENT_SIZE))

/*!
\def RCS512_ROUNDKEY_SIZE
* The size of the RCS-512 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_rcs_state struct.
*/
#define RCS512_ROUNDKEY_SIZE ((RCS512_ROUND_COUNT + 1) * (QSC_RCS_BLOCK_SIZE / RCS_ROUNDKEY_ELEMENT_SIZE))

/*!
\def RCS256_MKEY_LENGTH
* The size of the hba-rhx256 mac key array
*/
#define RCS256_MKEY_LENGTH 32

/*!
\def RCS512_MKEY_LENGTH
* The size of the hba-rhx512 mac key array
*/
#define RCS512_MKEY_LENGTH 64

/*!
\def RCS_NAME_LENGTH
* The HBA implementation specific name array length.
*/
#if defined(QSC_RCS_AUTHENTICATED)
#define RCS_NAME_LENGTH 17
#else
#define RCS_NAME_LENGTH 13
#endif

/*!
\def RCS_INFO_DEFLEN
* The size in bytes of the internal default information string.
*/
#define RCS_INFO_DEFLEN 9

#if defined(QSC_RCS_AUTHENTICATED)
static const uint8_t rcs256_name[RCS_NAME_LENGTH] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x52, 0x43, 0x53, 0x4B, 0x32, 0x35,
	0x36
};

static const uint8_t rcs512_name[RCS_NAME_LENGTH] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x52, 0x43, 0x53, 0x4B, 0x35, 0x31,
	0x32
};
#else
static const uint8_t rcs256_name[RCS_NAME_LENGTH] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x52, 0x43, 0x53
};

static const uint8_t rcs512_name[RCS_NAME_LENGTH] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x52, 0x43, 0x53
};
#endif

/* aes-ni and table-based fallback functions */

#if defined(QSC_RCS_AESNI_ENABLED)

static void rcs_transform_256(qsc_rcs_state* ctx, __m128i output[2], const __m128i input[2])
{
	const __m128i BLEND_MASK = _mm_set_epi32(0x80000000UL, 0x80800000UL, 0x80800000UL, 0x80808000UL);
	const __m128i SHIFT_MASK = { 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3 };
	const size_t HLFBLK = QSC_RCS_BLOCK_SIZE / 2;
	const size_t RNDCNT = ctx->roundkeylen - 3;
	size_t kctr;

	__m128i blk1 = _mm_loadu_si128(&input[0]);
	__m128i blk2 = _mm_loadu_si128(&input[1]);
	__m128i tmp1;
	__m128i tmp2;

	kctr = 0;
	blk1 = _mm_xor_si128(blk1, ctx->roundkeys[kctr]);
	++kctr;
	blk2 = _mm_xor_si128(blk2, ctx->roundkeys[kctr]);

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
		blk1 = _mm_aesenc_si128(tmp1, ctx->roundkeys[kctr]);
		++kctr;
		/* encrypt the second half-block */
		blk2 = _mm_aesenc_si128(tmp2, ctx->roundkeys[kctr]);
	}

	/* final block */
	tmp1 = _mm_blendv_epi8(blk1, blk2, BLEND_MASK);
	tmp2 = _mm_blendv_epi8(blk2, blk1, BLEND_MASK);
	tmp1 = _mm_shuffle_epi8(tmp1, SHIFT_MASK);
	tmp2 = _mm_shuffle_epi8(tmp2, SHIFT_MASK);
	++kctr;
	blk1 = _mm_aesenclast_si128(tmp1, ctx->roundkeys[kctr]);
	++kctr;
	blk2 = _mm_aesenclast_si128(tmp2, ctx->roundkeys[kctr]);

	/* store in output */
	_mm_storeu_si128(&output[0], blk1);
	_mm_storeu_si128(&output[1], blk2);
}

#if defined(QSC_SYSTEM_HAS_AVX512)

static void rcs_load2x128to512(const __m128i* k1, const __m128i* k2, __m512i* output)
{
	*output = _mm512_setzero_si512();
	*output = _mm512_inserti32x4(*output, *k1, 0);
	*output = _mm512_inserti32x4(*output, *k2, 1);
	*output = _mm512_inserti32x4(*output, *k1, 2);
	*output = _mm512_inserti32x4(*output, *k2, 3);
}

__m512i rcs_shuffle512(const __m512i* value, const __m512i* k0, const __m512i* k1, const __m512i* mask)
{
	return _mm512_or_si512(_mm512_shuffle_epi8(*value, _mm512_add_epi8(*mask, *k0)),
		_mm512_shuffle_epi8(_mm512_permutex_epi64(*value, 0x4E), _mm512_add_epi8(*mask, *k1)));
}

static void rcs_transform_512(qsc_rcs_state* ctx, __m512i* output, const __m512i* input)
{
	const __m512i NI512K0 = _mm512_set_epi64(17361641481138401520, 17361641481138401520, 8102099357864587376, 8102099357864587376,
		17361641481138401520, 17361641481138401520, 8102099357864587376, 8102099357864587376);
	const __m512i NI512K1 = _mm512_set_epi64(8102099357864587376, 8102099357864587376, 17361641481138401520, 17361641481138401520,
		8102099357864587376, 8102099357864587376, 17361641481138401520, 17361641481138401520);
	const __m512i SWMASKL = _mm512_setr_epi8(0, 17, 22, 23, 4, 5, 26, 27, 8, 9, 14, 31, 12, 13, 18, 19,
		16, 1, 6, 7, 20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2, 3,
		0, 17, 22, 23, 4, 5, 26, 27, 8, 9, 14, 31, 12, 13, 18, 19, 
		16, 1, 6, 7, 20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2, 3);

	const size_t RNDCNT = (ctx->roundkeylen / 2) - 2;
	size_t kctr;
	__m512i x;

	kctr = 0;
	x = *input;
	x = _mm512_xor_si512(x, ctx->roundkeysw[kctr]);

	while (kctr < RNDCNT)
	{
		++kctr;
		x = rcs_shuffle512(&x, &NI512K0, &NI512K1, &SWMASKL);
		x = _mm512_aesenc_epi128(x, ctx->roundkeysw[kctr]);
	}

	++kctr;
	x = rcs_shuffle512(&x, &NI512K0, &NI512K1, &SWMASKL);
	*output = _mm512_aesenclast_epi128(x, ctx->roundkeysw[kctr]);
}

#endif

static void rcs_ctr_transform(qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	const size_t HLFBLK = QSC_RCS_BLOCK_SIZE / 2;
	size_t i;
	size_t oft;

	oft = 0;

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (length >= RCS_AVX512_BLOCK)
	{
		uint8_t ctrblk[64];
		__m512i ctrw;
		__m512i inpw;
		__m512i otpw;

		/* initialize and pre-set the nonce */
		ctrw = _mm512_set1_epi64(0);
		qsc_memutils_copy(ctrblk, ctx->nonce, QSC_RCS_BLOCK_SIZE);
		qsc_memutils_copy(((uint8_t*)ctrblk + QSC_RCS_BLOCK_SIZE), ctx->nonce, QSC_RCS_BLOCK_SIZE);
		ctrw = _mm512_load_si512(ctrblk);
		ctrw = _mm512_add_epi64(ctrw, _mm512_set_epi64(0, 0, 0, 1, 0, 0, 0, 0));

		/* process 2 blocks in parallel */
		while (length >= RCS_AVX512_BLOCK)
		{
			/* encrypt the nonce */
			rcs_transform_512(ctx, &otpw, &ctrw);
			/* load the input */
			inpw = _mm512_loadu_si512((const __m512i*)((uint8_t*)input + oft));
			/* xor encrypted encrypted nonce with the input */
			otpw = _mm512_xor_si512(otpw, inpw);
			/* increments only the first 64 bits of the nonce; with ulong rollover that is 2^64 output blocks available */
			ctrw = _mm512_add_epi64(ctrw, _mm512_set_epi64(0, 0, 0, 2, 0, 0, 0, 2));
			/* store in output */
			_mm512_storeu_si512((__m512i*)((uint8_t*)output + oft), otpw);

			oft += RCS_AVX512_BLOCK;
			length -= RCS_AVX512_BLOCK;
		}

		/* store the last position of the nonce */
		_mm512_storeu_si512((__m512i*)ctrblk, ctrw);
		qsc_memutils_copy(ctx->nonce, ctrblk, QSC_RCS_BLOCK_SIZE);
	}

#endif

	while (length >= QSC_RCS_BLOCK_SIZE)
	{
		__m128i tmpn[2] = { _mm_loadu_si128((const __m128i*)ctx->nonce), _mm_loadu_si128((const __m128i*)((uint8_t*)ctx->nonce + HLFBLK)) };
		__m128i tmpo[2] = { 0 };

		rcs_transform_256(ctx, tmpo, tmpn);

		__m128i tmpi[2] = { _mm_loadu_si128((const __m128i*)((uint8_t*)input + oft)) , _mm_loadu_si128((const __m128i*)((uint8_t*)input + HLFBLK + oft)) };

		tmpo[0] = _mm_xor_si128(tmpo[0], tmpi[0]);
		tmpo[1] = _mm_xor_si128(tmpo[1], tmpi[1]);

		qsc_intutils_le8increment(ctx->nonce, QSC_RCS_BLOCK_SIZE);

		/* store in output */
		_mm_storeu_si128((__m128i*)((uint8_t*)output + oft), tmpo[0]);
		_mm_storeu_si128((__m128i*)((uint8_t*)output + HLFBLK + oft), tmpo[1]);

		length -= QSC_RCS_BLOCK_SIZE;
		oft += QSC_RCS_BLOCK_SIZE;
	}

	if (length != 0)
	{
		__m128i tmpn[2] = { _mm_loadu_si128((const __m128i*)ctx->nonce), _mm_loadu_si128((const __m128i*)((uint8_t*)ctx->nonce + HLFBLK)) };
		__m128i tmpo[2] = { 0 };
		uint8_t tmpb[QSC_RCS_BLOCK_SIZE] = { 0 };

		rcs_transform_256(ctx, tmpo, tmpn);

		/* store in tmp */
		_mm_storeu_si128((__m128i*)tmpb, tmpo[0]);
		_mm_storeu_si128((__m128i*)((uint8_t*)tmpb + HLFBLK), tmpo[1]);

		for (i = 0; i < length; ++i)
		{
			output[oft + i] = tmpb[i] ^ input[oft + i];
		}

		qsc_intutils_le8increment(ctx->nonce, QSC_RCS_BLOCK_SIZE);
	}
}

#else

/* rijndael rcs_rcon, and s-box constant tables */

static const uint8_t rcs_s_box[256] =
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

static const uint8_t rcs_is_box[256] =
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

static const uint32_t rcs_rcon[30] =
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

	for (i = 0; i < QSC_RCS_BLOCK_SIZE; i += sizeof(uint32_t))
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

	for (i = 0; i < QSC_RCS_BLOCK_SIZE; i += sizeof(uint32_t))
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
			dmy |= rcs_s_box[i];
		}
	}
	else
	{
		for (i = 0; i < 256; ++i)
		{
			dmy |= rcs_is_box[i];
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

	for (i = 0; i < QSC_RCS_BLOCK_SIZE; ++i)
	{
		state[i] = sbox[state[i]];
	}
}

static uint32_t rcs_substitution(uint32_t rot)
{
	uint32_t val;
	uint32_t res;

	val = rot & 0xFFU;
	res = rcs_s_box[val];
	val = (rot >> 8) & 0xFFU;
	res |= ((uint32_t)rcs_s_box[val] << 8);
	val = (rot >> 16) & 0xFFU;
	res |= ((uint32_t)rcs_s_box[val] << 16);
	val = (rot >> 24) & 0xFFU;

	return res | ((uint32_t)(rcs_s_box[val]) << 24);
}

static void rcs_transform_256(qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input)
{
	uint8_t buf[QSC_RCS_BLOCK_SIZE];
	size_t i;

	qsc_memutils_copy(buf, input, QSC_RCS_BLOCK_SIZE);
	rcs_add_roundkey(buf, ctx->roundkeys);
	rcs_prefetch_sbox(true);

	for (i = 1; i < ctx->rounds; ++i)
	{
		rcs_sub_bytes(buf, rcs_s_box);
		rcs_shift_rows(buf);
		rcs_mix_columns(buf);
		rcs_add_roundkey(buf, ctx->roundkeys + (i << 3));
	}

	rcs_sub_bytes(buf, rcs_s_box);
	rcs_shift_rows(buf);
	rcs_add_roundkey(buf, ctx->roundkeys + (ctx->rounds << 3));
	qsc_memutils_copy(output, buf, QSC_RCS_BLOCK_SIZE);
}

static void rcs_ctr_transform(qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(input != NULL);
	assert(output != NULL);

	size_t i;
	size_t oft;

	oft = 0;

	while (length >= QSC_RCS_BLOCK_SIZE)
	{
		rcs_transform_256(ctx, output + oft, ctx->nonce);
		qsc_memutils_xor(output + oft, input + oft, QSC_RCS_BLOCK_SIZE);
		qsc_intutils_le8increment(ctx->nonce, QSC_RCS_BLOCK_SIZE);

		length -= QSC_RCS_BLOCK_SIZE;
		oft += QSC_RCS_BLOCK_SIZE;
	}

	if (length != 0)
	{
		uint8_t tmpb[QSC_RCS_BLOCK_SIZE] = { 0 };

		rcs_transform_256(ctx, tmpb, ctx->nonce);

		for (i = 0; i < length; ++i)
		{
			output[oft + i] = tmpb[i] ^ input[oft + i];
		}

		qsc_intutils_le8increment(ctx->nonce, QSC_RCS_BLOCK_SIZE);
	}
}

#endif

static void rcs_mac_finalize(qsc_rcs_state* ctx, uint8_t* output)
{
	uint8_t ctr[sizeof(uint64_t)] = { 0 };
	uint64_t mctr = QSC_RCS_BLOCK_SIZE + ctx->counter + sizeof(uint64_t);

	qsc_intutils_le64to8(ctr, mctr);

	if (ctx->ctype == RCS256)
	{
#if defined(QSC_RCS_KPA_AUTHENTICATION)
		qsc_kpa_update(&ctx->kstate, ctr, sizeof(ctr));
		qsc_kpa_finalize(&ctx->kstate, output, QSC_RCS256_MAC_SIZE);
#else
		/* update with the counter */
		qsc_kmac_update(&ctx->kstate, keccak_rate_256, ctr, sizeof(ctr));
		/* finalize the mac and append code to output */
		qsc_kmac_finalize(&ctx->kstate, keccak_rate_256, output, QSC_RCS256_MAC_SIZE);
#endif
	}
	else
	{
#if defined(QSC_RCS_KPA_AUTHENTICATION)
		qsc_kpa_update(&ctx->kstate, ctr, sizeof(ctr));
		qsc_kpa_finalize(&ctx->kstate, output, QSC_RCS512_MAC_SIZE);
#else
		qsc_kmac_update(&ctx->kstate, keccak_rate_512, ctr, sizeof(ctr));
		qsc_kmac_finalize(&ctx->kstate, keccak_rate_512, output, QSC_RCS512_MAC_SIZE);
#endif
	}
}

static void rcs_mac_update(qsc_rcs_state* ctx, const uint8_t* input, size_t length)
{
#if defined(QSC_RCS_KPA_AUTHENTICATION)
		qsc_kpa_update(&ctx->kstate, input, length);
#else
	if (ctx->ctype == RCS256)
	{
		qsc_kmac_update(&ctx->kstate, keccak_rate_256, input, length);
	}
	else
	{
		qsc_kmac_update(&ctx->kstate, keccak_rate_512, input, length);
	}
#endif
}

static void rcs_secure_expand(qsc_rcs_state* ctx, const qsc_rcs_keyparams* keyparams)
{
	uint8_t sbuf[QSC_KECCAK_STATE_SIZE * sizeof(uint64_t)] = { 0 };
	qsc_keccak_state kstate;
	size_t i;
	size_t oft;
	size_t rlen;

	qsc_intutils_clear64(kstate.state, QSC_KECCAK_STATE_SIZE);

	if (ctx->ctype == RCS256)
	{
		uint8_t tmpr[RCS256_ROUNDKEY_SIZE * RCS_ROUNDKEY_ELEMENT_SIZE] = { 0 };

		/* initialize an instance of cSHAKE */
		qsc_cshake_initialize(&kstate, keccak_rate_256, keyparams->key, keyparams->keylen, rcs256_name, RCS_NAME_LENGTH, keyparams->info, keyparams->infolen);

		oft = 0;
		rlen = RCS256_ROUNDKEY_SIZE * RCS_ROUNDKEY_ELEMENT_SIZE;

		while (rlen != 0)
		{
			const size_t BLKLEN = (rlen > QSC_KECCAK_256_RATE) ? QSC_KECCAK_256_RATE : rlen;
			qsc_cshake_squeezeblocks(&kstate, keccak_rate_256, sbuf, 1);
			qsc_memutils_copy(tmpr + oft, sbuf, BLKLEN);

			oft += BLKLEN;
			rlen -= BLKLEN;
		}

#if defined(QSC_RCS_AESNI_ENABLED)
		const size_t RNKLEN = (QSC_RCS_BLOCK_SIZE / sizeof(__m128i)) * (ctx->rounds + 1);

		/* copy p-rand bytes to round keys */
		for (i = 0; i < RNKLEN; ++i)
		{
			ctx->roundkeys[i] = _mm_loadu_si128((const __m128i*)(tmpr + (i * sizeof(__m128i))));
		}

#else
		/* realign in big endian format for ACS test vectors; RCS is the fallback to the AES-NI implementation */
		for (i = 0; i < RCS256_ROUNDKEY_SIZE; ++i)
		{
			ctx->roundkeys[i] = qsc_intutils_be8to32(tmpr + (i * sizeof(uint32_t)));
		}
#endif

#if defined(QSC_RCS_AUTHENTICATED)
		/* use two permutation calls to seperate the cipher/mac key outputs to match the CEX implementation */
		qsc_cshake_squeezeblocks(&kstate, keccak_rate_256, sbuf, 1);
		uint8_t mkey[RCS256_MKEY_LENGTH];
		qsc_memutils_copy(mkey, sbuf, RCS256_MKEY_LENGTH);
		qsc_memutils_clear((uint8_t*)ctx->kstate.state, sizeof(ctx->kstate.state));

#if defined(QSC_RCS_KPA_AUTHENTICATION)
		qsc_kpa_initialize(&ctx->kstate, mkey, sizeof(mkey), NULL, 0);
#else
		qsc_kmac_initialize(&ctx->kstate, keccak_rate_256, mkey, sizeof(mkey), NULL, 0);
#endif
		/* clear the shake buffer */
		qsc_intutils_clear64(kstate.state, QSC_KECCAK_STATE_SIZE);
#endif
	}
	else
	{
		uint8_t tmpr[RCS512_ROUNDKEY_SIZE * RCS_ROUNDKEY_ELEMENT_SIZE] = { 0 };

		/* initialize an instance of cSHAKE */
		qsc_cshake_initialize(&kstate, keccak_rate_512, keyparams->key, keyparams->keylen, rcs512_name, RCS_NAME_LENGTH, keyparams->info, keyparams->infolen);

		oft = 0;
		rlen = RCS512_ROUNDKEY_SIZE * RCS_ROUNDKEY_ELEMENT_SIZE;

		while (rlen != 0)
		{
			const size_t BLKLEN = (rlen > QSC_KECCAK_512_RATE) ? QSC_KECCAK_512_RATE : rlen;
			qsc_cshake_squeezeblocks(&kstate, keccak_rate_512, sbuf, 1);
			qsc_memutils_copy(tmpr + oft, sbuf, BLKLEN);
			oft += BLKLEN;
			rlen -= BLKLEN;
		}

#if defined(QSC_RCS_AESNI_ENABLED)
		const size_t RNKLEN = (QSC_RCS_BLOCK_SIZE / sizeof(__m128i)) * (ctx->rounds + 1);

		/* copy p-rand bytes to round keys */
		for (i = 0; i < RNKLEN; ++i)
		{
			ctx->roundkeys[i] = _mm_loadu_si128((const __m128i*)(tmpr + (i * sizeof(__m128i))));
		}
#else
		/* realign in big endian format for ACS test vectors; RCS is the fallback to the AES-NI implementation */
		for (i = 0; i < RCS512_ROUNDKEY_SIZE; ++i)
		{
			ctx->roundkeys[i] = qsc_intutils_be8to32(tmpr + (i * sizeof(uint32_t)));
		}
#endif

#if defined(QSC_RCS_AUTHENTICATED)
		/* use two permutation calls (no buffering) to seperate the cipher/mac key outputs to match the CEX implementation */
		qsc_cshake_squeezeblocks(&kstate, keccak_rate_512, sbuf, 1);
		uint8_t mkey[RCS512_MKEY_LENGTH];
		qsc_memutils_copy(mkey, sbuf, RCS512_MKEY_LENGTH);
		qsc_memutils_clear((uint8_t*)ctx->kstate.state, sizeof(ctx->kstate.state));

#if defined(QSC_RCS_KPA_AUTHENTICATION)
		qsc_kpa_initialize(&ctx->kstate, mkey, sizeof(mkey), NULL, 0);
#else
		qsc_kmac_initialize(&ctx->kstate, keccak_rate_512, mkey, sizeof(mkey), NULL, 0);
#endif
		/* clear the shake buffer */
		qsc_intutils_clear64(kstate.state, QSC_KECCAK_STATE_SIZE);
#endif

	}

#if defined(QSC_RCS_AESNI_ENABLED)
#	if defined(QSC_SYSTEM_HAS_AVX512)
	/* store the avx-512 round keys */
	qsc_memutils_clear((uint8_t*)ctx->roundkeysw, sizeof(ctx->roundkeysw));

	for (i = 0; i < ctx->roundkeylen; i += 2)
	{
		rcs_load2x128to512(&ctx->roundkeys[i], &ctx->roundkeys[i + 1], &ctx->roundkeysw[i / 2]);
	}
#	endif
#endif
}

/* rcs common */

void qsc_rcs_dispose(qsc_rcs_state* ctx)
{
	if (ctx != NULL)
	{
#if defined(QSC_RCS_AUTHENTICATED)
#	if defined(QSC_RCS_KPA_AUTHENTICATION)
		qsc_kpa_dispose(&ctx->kstate);
#	else
		qsc_keccak_dispose(&ctx->kstate);
#	endif
#endif

#if defined(QSC_RCS_AESNI_ENABLED)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		qsc_memutils_clear((uint8_t*)ctx->roundkeysw, sizeof(ctx->roundkeysw));
#	endif
#endif

		qsc_memutils_clear((uint8_t*)ctx->roundkeys, sizeof(ctx->roundkeys));
		ctx->nonce = NULL;
		ctx->counter = 0;
		ctx->ctype = RCS256;
		ctx->roundkeylen = 0;
		ctx->rounds = 0;
		ctx->encrypt = false;
	}
}

void qsc_rcs_initialize(qsc_rcs_state* ctx, const qsc_rcs_keyparams* keyparams, bool encryption)
{
	assert(ctx != NULL);
	assert(keyparams->nonce != NULL);
	assert(keyparams->key != NULL);
	assert(keyparams->keylen == QSC_RCS256_KEY_SIZE || keyparams->keylen == QSC_RCS512_KEY_SIZE);

	ctx->ctype = keyparams->keylen == QSC_RCS512_KEY_SIZE ? RCS512 : RCS256;
	qsc_memutils_clear((uint8_t*)ctx->roundkeys, sizeof(ctx->roundkeys));
	ctx->nonce = keyparams->nonce;
	ctx->counter = 1;
	ctx->encrypt = encryption;


	if (ctx->ctype == RCS256)
	{
		/* initialize rcs state */
		ctx->roundkeylen = RCS256_ROUNDKEY_SIZE;
		ctx->rounds = 22;
	}
	else
	{
		/* initialize rcs state */
		ctx->roundkeylen = RCS512_ROUNDKEY_SIZE;
		ctx->rounds = 30;
	}

	/* generate the cipher and mac keys */
	rcs_secure_expand(ctx, keyparams);
}

void qsc_rcs_set_associated(qsc_rcs_state* ctx, const uint8_t* data, size_t length)
{
	assert(ctx != NULL);
	assert(data != NULL);
	assert(length != 0);

	if (length != 0)
	{
		uint8_t code[sizeof(uint32_t)] = { 0 };

		/* add the ad data to the hash */
		rcs_mac_update(ctx, data, length);
		/* add the length of the ad */
		qsc_intutils_le32to8(code, (uint32_t)length);
		rcs_mac_update(ctx, code, sizeof(code));
	}
}

bool qsc_rcs_transform(qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(output != NULL);
	assert(input != NULL);

	bool res;

#if defined(QSC_RCS_AUTHENTICATED)

	res = false;

	/* update the processed bytes counter */
	ctx->counter += length;

	/* update the mac with the current nonce position */
	rcs_mac_update(ctx, ctx->nonce, QSC_RCS_BLOCK_SIZE);

	if (ctx->encrypt)
	{
		/* transform the plain-text with the counter-mode cipher */
		rcs_ctr_transform(ctx, output, input, length);

		/* update the mac with the cipher-text */
		rcs_mac_update(ctx, output, length);

		/* mac the cipher-text appending the code to the end of the array */
		rcs_mac_finalize(ctx, output + length);
		res = true;
	}
	else
	{
		/* update the mac with the cipher-text */
		rcs_mac_update(ctx, input, length);

		if (ctx->ctype == RCS256)
		{
			uint8_t code[QSC_RCS256_MAC_SIZE] = { 0 };

			/* mac the cipher-text to a temp array for comparison */
			rcs_mac_finalize(ctx, code);

			/* test the mac for equality, bypassing the transform if the mac check fails */
			if (qsc_intutils_verify(code, input + length, QSC_RCS256_MAC_SIZE) == 0)
			{
				/* transform the plain-text with the counter-mode cipher */
				rcs_ctr_transform(ctx, output, input, length);
				res = true;
			}
		}
		else
		{
			uint8_t code[QSC_RCS512_MAC_SIZE] = { 0 };

			rcs_mac_finalize(ctx, code);

			if (qsc_intutils_verify(code, input + length, QSC_RCS512_MAC_SIZE) == 0)
			{
				rcs_ctr_transform(ctx, output, input, length);
				res = true;
			}
		}
	}

#else

	rcs_ctr_transform(ctx, output, input, length);
	res = true;

#endif

	return res;
}