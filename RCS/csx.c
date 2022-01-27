#include "csx.h"
#include "intutils.h"
#include "memutils.h"

#if defined(QSC_SYSTEM_HAS_AVX)
#	include "intrinsics.h"
#endif
#include <stdlib.h>

/*!
\def CSX_ROUND_COUNT
* \brief The number of mixing rounds used by CSX-512
*/
#define CSX_ROUND_COUNT 40

/*!
\def CSX_NAME_LENGTH
* \brief The byte size of the name array
*/
#define CSX_NAME_LENGTH 14

#define CSX_AVX512_BLOCK (8 * QSC_CSX_BLOCK_SIZE)
#define CSX_AVX2_BLOCK (4 * QSC_CSX_BLOCK_SIZE)

static const uint8_t csx_info[QSC_CSX_INFO_SIZE] =
{
	0x43, 0x53, 0x58, 0x35, 0x31, 0x32, 0x20, 0x4B, 0x4D, 0x41, 0x43, 0x20, 0x61, 0x75, 0x74, 0x68,
	0x65, 0x6E, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x76, 0x65, 0x72, 0x2E, 0x20,
	0x31, 0x63, 0x20, 0x43, 0x45, 0x58, 0x2B, 0x2B, 0x20, 0x6C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79
};

#if	defined(QSC_CSX_AUTHENTICATED)
static const uint8_t csx_name[CSX_NAME_LENGTH] =
{
	0x43, 0x53, 0x58, 0x35, 0x31, 0x32, 0x2D, 0x4B, 0x4D, 0x41, 0x43, 0x35, 0x31, 0x32
};

#	if defined(QSC_CSX_AUTH_KMACR12)
#		define QSC_CSX_AUTH_KMACR12
static const uint8_t csx_kmacr12_name[CSX_NAME_LENGTH] =
{
	0x43, 0x53, 0x58, 0x35, 0x31, 0x32, 0x2D, 0x4B, 0x4D, 0x41, 0x43, 0x52, 0x31, 0x32
};
#	endif
#endif

static void csx_increment(qsc_csx_state* ctx)
{
	++ctx->state[12];

	if (ctx->state[12] == 0)
	{
		++ctx->state[13];
	}
}

static void csx_permute_p1024c(const qsc_csx_state* ctx, uint8_t* output)
{
	uint64_t X0 = ctx->state[0];
	uint64_t X1 = ctx->state[1];
	uint64_t X2 = ctx->state[2];
	uint64_t X3 = ctx->state[3];
	uint64_t X4 = ctx->state[4];
	uint64_t X5 = ctx->state[5];
	uint64_t X6 = ctx->state[6];
	uint64_t X7 = ctx->state[7];
	uint64_t X8 = ctx->state[8];
	uint64_t X9 = ctx->state[9];
	uint64_t X10 = ctx->state[10];
	uint64_t X11 = ctx->state[11];
	uint64_t X12 = ctx->state[12];
	uint64_t X13 = ctx->state[13];
	uint64_t X14 = ctx->state[14];
	uint64_t X15 = ctx->state[15];
	size_t ctr = CSX_ROUND_COUNT;

	/* new rotational constants=
	38,19,10,55
	33,4,51,13
	16,34,56,51
	4,53,42,41
	34,41,59,17
	23,31,37,20
	31,44,47,46
	12,47,44,30 */

	while (ctr != 0)
	{
		/* round n */
		X0 += X4;
		X12 = qsc_intutils_rotl64(X12 ^ X0, 38);
		X8 += X12;
		X4 = qsc_intutils_rotl64(X4 ^ X8, 19);
		X0 += X4;
		X12 = qsc_intutils_rotl64(X12 ^ X0, 10);
		X8 += X12;
		X4 = qsc_intutils_rotl64(X4 ^ X8, 55);
		X1 += X5;
		X13 = qsc_intutils_rotl64(X13 ^ X1, 33);
		X9 += X13;
		X5 = qsc_intutils_rotl64(X5 ^ X9, 4);
		X1 += X5;
		X13 = qsc_intutils_rotl64(X13 ^ X1, 51);
		X9 += X13;
		X5 = qsc_intutils_rotl64(X5 ^ X9, 13);
		X2 += X6;
		X14 = qsc_intutils_rotl64(X14 ^ X2, 16);
		X10 += X14;
		X6 = qsc_intutils_rotl64(X6 ^ X10, 34);
		X2 += X6;
		X14 = qsc_intutils_rotl64(X14 ^ X2, 56);
		X10 += X14;
		X6 = qsc_intutils_rotl64(X6 ^ X10, 51);
		X3 += X7;
		X15 = qsc_intutils_rotl64(X15 ^ X3, 4);
		X11 += X15;
		X7 = qsc_intutils_rotl64(X7 ^ X11, 53);
		X3 += X7;
		X15 = qsc_intutils_rotl64(X15 ^ X3, 42);
		X11 += X15;
		X7 = qsc_intutils_rotl64(X7 ^ X11, 41);
		/* round n+1 */
		X0 += X5;
		X15 = qsc_intutils_rotl64(X15 ^ X0, 34);
		X10 += X15;
		X5 = qsc_intutils_rotl64(X5 ^ X10, 41);
		X0 += X5;
		X15 = qsc_intutils_rotl64(X15 ^ X0, 59);
		X10 += X15;
		X5 = qsc_intutils_rotl64(X5 ^ X10, 17);
		X1 += X6;
		X12 = qsc_intutils_rotl64(X12 ^ X1, 23);
		X11 += X12;
		X6 = qsc_intutils_rotl64(X6 ^ X11, 31);
		X1 += X6;
		X12 = qsc_intutils_rotl64(X12 ^ X1, 37);
		X11 += X12;
		X6 = qsc_intutils_rotl64(X6 ^ X11, 20);
		X2 += X7;
		X13 = qsc_intutils_rotl64(X13 ^ X2, 31);
		X8 += X13;
		X7 = qsc_intutils_rotl64(X7 ^ X8, 44);
		X2 += X7;
		X13 = qsc_intutils_rotl64(X13 ^ X2, 47);
		X8 += X13;
		X7 = qsc_intutils_rotl64(X7 ^ X8, 46);
		X3 += X4;
		X14 = qsc_intutils_rotl64(X14 ^ X3, 12);
		X9 += X14;
		X4 = qsc_intutils_rotl64(X4 ^ X9, 47);
		X3 += X4;
		X14 = qsc_intutils_rotl64(X14 ^ X3, 44);
		X9 += X14;
		X4 = qsc_intutils_rotl64(X4 ^ X9, 30);
		ctr -= 2;
	}

	qsc_intutils_le64to8(output, X0 + ctx->state[0]);
	qsc_intutils_le64to8(output + 8, X1 + ctx->state[1]);
	qsc_intutils_le64to8(output + 16, X2 + ctx->state[2]);
	qsc_intutils_le64to8(output + 24, X3 + ctx->state[3]);
	qsc_intutils_le64to8(output + 32, X4 + ctx->state[4]);
	qsc_intutils_le64to8(output + 40, X5 + ctx->state[5]);
	qsc_intutils_le64to8(output + 48, X6 + ctx->state[6]);
	qsc_intutils_le64to8(output + 56, X7 + ctx->state[7]);
	qsc_intutils_le64to8(output + 64, X8 + ctx->state[8]);
	qsc_intutils_le64to8(output + 72, X9 + ctx->state[9]);
	qsc_intutils_le64to8(output + 80, X10 + ctx->state[10]);
	qsc_intutils_le64to8(output + 88, X11 + ctx->state[11]);
	qsc_intutils_le64to8(output + 96, X12 + ctx->state[12]);
	qsc_intutils_le64to8(output + 104, X13 + ctx->state[13]);
	qsc_intutils_le64to8(output + 112, X14 + ctx->state[14]);
	qsc_intutils_le64to8(output + 120, X15 + ctx->state[15]);
}

#if defined(QSC_SYSTEM_HAS_AVX512)

typedef struct
{
	__m512i state[16];
	__m512i outw[16];
} csx_avx512_state;

inline static __m512i csx_rotl512(const __m512i x, uint32_t shift)
{
	return _mm512_or_si512(_mm512_slli_epi64(x, shift), _mm512_srli_epi64(x, 64 - shift));
}

static __m512i csx_load512(const uint8_t* v)
{
	const uint64_t* v64 = (uint64_t*)v;

	return _mm512_set_epi64(v64[0], v64[16], v64[32], v64[48], v64[64], v64[80], v64[96], v64[112]);
}

static void csx_store512(uint8_t* output, const __m512i x)
{
	uint64_t tmp[8];

	_mm512_storeu_si512((__m512i*)tmp, x);

	qsc_intutils_le64to8(output, tmp[7]);
	qsc_intutils_le64to8((output + 128), tmp[6]);
	qsc_intutils_le64to8((output + 256), tmp[5]);
	qsc_intutils_le64to8((output + 384), tmp[4]);
	qsc_intutils_le64to8((output + 512), tmp[3]);
	qsc_intutils_le64to8((output + 640), tmp[2]);
	qsc_intutils_le64to8((output + 768), tmp[1]);
	qsc_intutils_le64to8((output + 896), tmp[0]);
}

static void leincrement_512(__m512i* v)
{
	const __m512i NAD = _mm512_set_epi64(8, 8, 8, 8, 8, 8, 8, 8);

	*v = _mm512_add_epi64(*v, NAD);
}

static void csx_permute_p8x1024h(csx_avx512_state* ctx)
{
	__m512i x0;
	__m512i x1;
	__m512i x2;
	__m512i x3;
	__m512i x4;
	__m512i x5;
	__m512i x6;
	__m512i x7;
	__m512i x8;
	__m512i x9;
	__m512i x10;
	__m512i x11;
	__m512i x12;
	__m512i x13;
	__m512i x14;
	__m512i x15;
	size_t ctr;

	x0 = ctx->state[0];
	x1 = ctx->state[1];
	x2 = ctx->state[2];
	x3 = ctx->state[3];
	x4 = ctx->state[4];
	x5 = ctx->state[5];
	x6 = ctx->state[6];
	x7 = ctx->state[7];
	x8 = ctx->state[8];
	x9 = ctx->state[9];
	x10 = ctx->state[10];
	x11 = ctx->state[11];
	x12 = ctx->state[12];
	x13 = ctx->state[13];
	x14 = ctx->state[14];
	x15 = ctx->state[15];
	ctr = CSX_ROUND_COUNT;

	/* new rotational constants=
	38,19,10,55
	33,4,51,13
	16,34,56,51
	4,53,42,41
	34,41,59,17
	23,31,37,20
	31,44,47,46
	12,47,44,30 */

	while (ctr != 0)
	{
		/* round n */
		x0 = _mm512_add_epi64(x0, x4);
		x12 = csx_rotl512(_mm512_xor_si512(x12, x0), 38);
		x8 = _mm512_add_epi64(x8, x12);
		x4 = csx_rotl512(_mm512_xor_si512(x4, x8), 19);
		x0 = _mm512_add_epi64(x0, x4);
		x12 = csx_rotl512(_mm512_xor_si512(x12, x0), 10);
		x8 = _mm512_add_epi64(x8, x12);
		x4 = csx_rotl512(_mm512_xor_si512(x4, x8), 55);
		x1 = _mm512_add_epi64(x1, x5);
		x13 = csx_rotl512(_mm512_xor_si512(x13, x1), 33);
		x9 = _mm512_add_epi64(x9, x13);
		x5 = csx_rotl512(_mm512_xor_si512(x5, x9), 4);
		x1 = _mm512_add_epi64(x1, x5);
		x13 = csx_rotl512(_mm512_xor_si512(x13, x1), 51);
		x9 = _mm512_add_epi64(x9, x13);
		x5 = csx_rotl512(_mm512_xor_si512(x5, x9), 13);
		x2 = _mm512_add_epi64(x2, x6);
		x14 = csx_rotl512(_mm512_xor_si512(x14, x2), 16);
		x10 = _mm512_add_epi64(x10, x14);
		x6 = csx_rotl512(_mm512_xor_si512(x6, x10), 34);
		x2 = _mm512_add_epi64(x2, x6);
		x14 = csx_rotl512(_mm512_xor_si512(x14, x2), 56);
		x10 = _mm512_add_epi64(x10, x14);
		x6 = csx_rotl512(_mm512_xor_si512(x6, x10), 51);
		x3 = _mm512_add_epi64(x3, x7);
		x15 = csx_rotl512(_mm512_xor_si512(x15, x3), 4);
		x11 = _mm512_add_epi64(x11, x15);
		x7 = csx_rotl512(_mm512_xor_si512(x7, x11), 53);
		x3 = _mm512_add_epi64(x3, x7);
		x15 = csx_rotl512(_mm512_xor_si512(x15, x3), 42);
		x11 = _mm512_add_epi64(x11, x15);
		x7 = csx_rotl512(_mm512_xor_si512(x7, x11), 41);
		/* round n+1 */
		x0 = _mm512_add_epi64(x0, x5);
		x15 = csx_rotl512(_mm512_xor_si512(x15, x0), 34);
		x10 = _mm512_add_epi64(x10, x15);
		x5 = csx_rotl512(_mm512_xor_si512(x5, x10), 41);
		x0 = _mm512_add_epi64(x0, x5);
		x15 = csx_rotl512(_mm512_xor_si512(x15, x0), 59);
		x10 = _mm512_add_epi64(x10, x15);
		x5 = csx_rotl512(_mm512_xor_si512(x5, x10), 17);
		x1 = _mm512_add_epi64(x1, x6);
		x12 = csx_rotl512(_mm512_xor_si512(x12, x1), 23);
		x11 = _mm512_add_epi64(x11, x12);
		x6 = csx_rotl512(_mm512_xor_si512(x6, x11), 31);
		x1 = _mm512_add_epi64(x1, x6);
		x12 = csx_rotl512(_mm512_xor_si512(x12, x1), 37);
		x11 = _mm512_add_epi64(x11, x12);
		x6 = csx_rotl512(_mm512_xor_si512(x6, x11), 20);
		x2 = _mm512_add_epi64(x2, x7);
		x13 = csx_rotl512(_mm512_xor_si512(x13, x2), 31);
		x8 = _mm512_add_epi64(x8, x13);
		x7 = csx_rotl512(_mm512_xor_si512(x7, x8), 44);
		x2 = _mm512_add_epi64(x2, x7);
		x13 = csx_rotl512(_mm512_xor_si512(x13, x2), 47);
		x8 = _mm512_add_epi64(x8, x13);
		x7 = csx_rotl512(_mm512_xor_si512(x7, x8), 46);
		x3 = _mm512_add_epi64(x3, x4);
		x14 = csx_rotl512(_mm512_xor_si512(x14, x3), 12);
		x9 = _mm512_add_epi64(x9, x14);
		x4 = csx_rotl512(_mm512_xor_si512(x4, x9), 47);
		x3 = _mm512_add_epi64(x3, x4);
		x14 = csx_rotl512(_mm512_xor_si512(x14, x3), 44);
		x9 = _mm512_add_epi64(x9, x14);
		x4 = csx_rotl512(_mm512_xor_si512(x4, x9), 30);
		ctr -= 2;
	}

	ctx->outw[0] = _mm512_add_epi64(x0, ctx->state[0]);
	ctx->outw[1] = _mm512_add_epi64(x1, ctx->state[1]);
	ctx->outw[2] = _mm512_add_epi64(x2, ctx->state[2]);
	ctx->outw[3] = _mm512_add_epi64(x3, ctx->state[3]);
	ctx->outw[4] = _mm512_add_epi64(x4, ctx->state[4]);
	ctx->outw[5] = _mm512_add_epi64(x5, ctx->state[5]);
	ctx->outw[6] = _mm512_add_epi64(x6, ctx->state[6]);
	ctx->outw[7] = _mm512_add_epi64(x7, ctx->state[7]);
	ctx->outw[8] = _mm512_add_epi64(x8, ctx->state[8]);
	ctx->outw[9] = _mm512_add_epi64(x9, ctx->state[9]);
	ctx->outw[10] = _mm512_add_epi64(x10, ctx->state[10]);
	ctx->outw[11] = _mm512_add_epi64(x11, ctx->state[11]);
	ctx->outw[12] = _mm512_add_epi64(x12, ctx->state[12]);
	ctx->outw[13] = _mm512_add_epi64(x13, ctx->state[13]);
	ctx->outw[14] = _mm512_add_epi64(x14, ctx->state[14]);
	ctx->outw[15] = _mm512_add_epi64(x15, ctx->state[15]);
}


#elif defined(QSC_SYSTEM_HAS_AVX2)

typedef struct
{
	__m256i state[16];
	__m256i outw[16];
} csx_avx256_state;

static __m256i csx_rotl256(const __m256i x, size_t shift)
{
	return _mm256_or_si256(_mm256_slli_epi64(x, (int32_t)shift), _mm256_srli_epi64(x, 64 - (int32_t)shift));
}

static __m256i csx_load256(const uint8_t* v)
{
	const uint64_t* v64 = (const uint64_t*)v;

	return _mm256_set_epi64x(v64[0], v64[16], v64[32], v64[48]);
}

static void csx_store256(uint8_t* output, const __m256i x)
{
	QSC_ALIGN(32) uint64_t tmp[4];

	_mm256_storeu_si256((__m256i*)tmp, x);

	qsc_intutils_le64to8(output, tmp[3]);
	qsc_intutils_le64to8((output + 128), tmp[2]);
	qsc_intutils_le64to8((output + 256), tmp[1]);
	qsc_intutils_le64to8((output + 384), tmp[0]);
}

static void leincrement_256(__m256i* v)
{
	const __m256i NAD = _mm256_set_epi64x(4, 4, 4, 4);

	*v = _mm256_add_epi64(*v, NAD);
}

static void csx_permute_p4x1024h(csx_avx256_state* ctx)
{
	__m256i x0;
	__m256i x1;
	__m256i x2;
	__m256i x3;
	__m256i x4;
	__m256i x5;
	__m256i x6;
	__m256i x7;
	__m256i x8;
	__m256i x9;
	__m256i x10;
	__m256i x11;
	__m256i x12;
	__m256i x13;
	__m256i x14;
	__m256i x15;
	size_t ctr;

	x0 = ctx->state[0];
	x1 = ctx->state[1];
	x2 = ctx->state[2];
	x3 = ctx->state[3];
	x4 = ctx->state[4];
	x5 = ctx->state[5];
	x6 = ctx->state[6];
	x7 = ctx->state[7];
	x8 = ctx->state[8];
	x9 = ctx->state[9];
	x10 = ctx->state[10];
	x11 = ctx->state[11];
	x12 = ctx->state[12];
	x13 = ctx->state[13];
	x14 = ctx->state[14];
	x15 = ctx->state[15];
	ctr = CSX_ROUND_COUNT;

	/* new rotational constants=
	38,19,10,55
	33,4,51,13
	16,34,56,51
	4,53,42,41
	34,41,59,17
	23,31,37,20
	31,44,47,46
	12,47,44,30 */

	while (ctr != 0)
	{
		/* round n */
		x0 = _mm256_add_epi64(x0, x4);
		x12 = csx_rotl256(_mm256_xor_si256(x12, x0), 38);
		x8 = _mm256_add_epi64(x8, x12);
		x4 = csx_rotl256(_mm256_xor_si256(x4, x8), 19);
		x0 = _mm256_add_epi64(x0, x4);
		x12 = csx_rotl256(_mm256_xor_si256(x12, x0), 10);
		x8 = _mm256_add_epi64(x8, x12);
		x4 = csx_rotl256(_mm256_xor_si256(x4, x8), 55);
		x1 = _mm256_add_epi64(x1, x5);
		x13 = csx_rotl256(_mm256_xor_si256(x13, x1), 33);
		x9 = _mm256_add_epi64(x9, x13);
		x5 = csx_rotl256(_mm256_xor_si256(x5, x9), 4);
		x1 = _mm256_add_epi64(x1, x5);
		x13 = csx_rotl256(_mm256_xor_si256(x13, x1), 51);
		x9 = _mm256_add_epi64(x9, x13);
		x5 = csx_rotl256(_mm256_xor_si256(x5, x9), 13);
		x2 = _mm256_add_epi64(x2, x6);
		x14 = csx_rotl256(_mm256_xor_si256(x14, x2), 16);
		x10 = _mm256_add_epi64(x10, x14);
		x6 = csx_rotl256(_mm256_xor_si256(x6, x10), 34);
		x2 = _mm256_add_epi64(x2, x6);
		x14 = csx_rotl256(_mm256_xor_si256(x14, x2), 56);
		x10 = _mm256_add_epi64(x10, x14);
		x6 = csx_rotl256(_mm256_xor_si256(x6, x10), 51);
		x3 = _mm256_add_epi64(x3, x7);
		x15 = csx_rotl256(_mm256_xor_si256(x15, x3), 4);
		x11 = _mm256_add_epi64(x11, x15);
		x7 = csx_rotl256(_mm256_xor_si256(x7, x11), 53);
		x3 = _mm256_add_epi64(x3, x7);
		x15 = csx_rotl256(_mm256_xor_si256(x15, x3), 42);
		x11 = _mm256_add_epi64(x11, x15);
		x7 = csx_rotl256(_mm256_xor_si256(x7, x11), 41);
		/* round n+1 */
		x0 = _mm256_add_epi64(x0, x5);
		x15 = csx_rotl256(_mm256_xor_si256(x15, x0), 34);
		x10 = _mm256_add_epi64(x10, x15);
		x5 = csx_rotl256(_mm256_xor_si256(x5, x10), 41);
		x0 = _mm256_add_epi64(x0, x5);
		x15 = csx_rotl256(_mm256_xor_si256(x15, x0), 59);
		x10 = _mm256_add_epi64(x10, x15);
		x5 = csx_rotl256(_mm256_xor_si256(x5, x10), 17);
		x1 = _mm256_add_epi64(x1, x6);
		x12 = csx_rotl256(_mm256_xor_si256(x12, x1), 23);
		x11 = _mm256_add_epi64(x11, x12);
		x6 = csx_rotl256(_mm256_xor_si256(x6, x11), 31);
		x1 = _mm256_add_epi64(x1, x6);
		x12 = csx_rotl256(_mm256_xor_si256(x12, x1), 37);
		x11 = _mm256_add_epi64(x11, x12);
		x6 = csx_rotl256(_mm256_xor_si256(x6, x11), 20);
		x2 = _mm256_add_epi64(x2, x7);
		x13 = csx_rotl256(_mm256_xor_si256(x13, x2), 31);
		x8 = _mm256_add_epi64(x8, x13);
		x7 = csx_rotl256(_mm256_xor_si256(x7, x8), 44);
		x2 = _mm256_add_epi64(x2, x7);
		x13 = csx_rotl256(_mm256_xor_si256(x13, x2), 47);
		x8 = _mm256_add_epi64(x8, x13);
		x7 = csx_rotl256(_mm256_xor_si256(x7, x8), 46);
		x3 = _mm256_add_epi64(x3, x4);
		x14 = csx_rotl256(_mm256_xor_si256(x14, x3), 12);
		x9 = _mm256_add_epi64(x9, x14);
		x4 = csx_rotl256(_mm256_xor_si256(x4, x9), 47);
		x3 = _mm256_add_epi64(x3, x4);
		x14 = csx_rotl256(_mm256_xor_si256(x14, x3), 44);
		x9 = _mm256_add_epi64(x9, x14);
		x4 = csx_rotl256(_mm256_xor_si256(x4, x9), 30);
		ctr -= 2;
	}

	ctx->outw[0] = _mm256_add_epi64(x0, ctx->state[0]);
	ctx->outw[1] = _mm256_add_epi64(x1, ctx->state[1]);
	ctx->outw[2] = _mm256_add_epi64(x2, ctx->state[2]);
	ctx->outw[3] = _mm256_add_epi64(x3, ctx->state[3]);
	ctx->outw[4] = _mm256_add_epi64(x4, ctx->state[4]);
	ctx->outw[5] = _mm256_add_epi64(x5, ctx->state[5]);
	ctx->outw[6] = _mm256_add_epi64(x6, ctx->state[6]);
	ctx->outw[7] = _mm256_add_epi64(x7, ctx->state[7]);
	ctx->outw[8] = _mm256_add_epi64(x8, ctx->state[8]);
	ctx->outw[9] = _mm256_add_epi64(x9, ctx->state[9]);
	ctx->outw[10] = _mm256_add_epi64(x10, ctx->state[10]);
	ctx->outw[11] = _mm256_add_epi64(x11, ctx->state[11]);
	ctx->outw[12] = _mm256_add_epi64(x12, ctx->state[12]);
	ctx->outw[13] = _mm256_add_epi64(x13, ctx->state[13]);
	ctx->outw[14] = _mm256_add_epi64(x14, ctx->state[14]);
	ctx->outw[15] = _mm256_add_epi64(x15, ctx->state[15]);
}

#endif

static void csx_mac_update(qsc_csx_state* ctx, const uint8_t* input, size_t length)
{
#if defined(QSC_CSX_AUTH_KMACR12)
	qsc_keccak_update(&ctx->kstate, qsc_keccak_rate_512, input, length, QSC_KECCAK_PERMUTATION_MIN_ROUNDS);
#else
	qsc_kmac_update(&ctx->kstate, qsc_keccak_rate_512, input, length);
#endif
}

static void csx_transform(qsc_csx_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	size_t oft;

	oft = 0;

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (length >= CSX_AVX512_BLOCK)
	{
		csx_avx512_state ctxw;
		__m512i tmpin;
		size_t i;

		for (i = 0; i < 16; ++i)
		{
			uint64_t x = ctx->state[i];
			ctxw.state[i] = _mm512_set1_epi64(x);
		}

		/* initialize the nonce */
		ctxw.state[12] = _mm512_add_epi64(ctxw.state[12], _mm512_set_epi64(0, 1, 2, 3, 4, 5, 6, 7));

		/* process 8 blocks in parallel (uses avx512 if available) */
		while (length >= CSX_AVX512_BLOCK)
		{
			csx_permute_p8x1024h(&ctxw);

			for (i = 0; i < 16; ++i)
			{
				tmpin = csx_load512((input + oft + (i * 8)));
				ctxw.outw[i] = _mm512_xor_si512(ctxw.outw[i], tmpin);
				csx_store512((output + oft + (i * 8)), ctxw.outw[i]);
			}

			leincrement_512(&ctxw.state[12]);
			oft += CSX_AVX512_BLOCK;
			length -= CSX_AVX512_BLOCK;
		}

		uint8_t ctrblk[64];
		/* store the nonce */
		_mm512_storeu_si512((__m512i*)ctrblk, ctxw.state[12]);
		ctx->state[12] = qsc_intutils_le8to64((ctrblk + 56));
		_mm512_storeu_si512((__m512i*)ctrblk, ctxw.state[13]);
		ctx->state[13] = qsc_intutils_le8to64((ctrblk + 56));
	}

#elif defined(QSC_SYSTEM_HAS_AVX2)

	if (length >= CSX_AVX2_BLOCK)
	{
		csx_avx256_state ctxw;
		__m256i tmpin;
		size_t i;

		for (i = 0; i < 16; ++i)
		{
			uint64_t x = ctx->state[i];
			ctxw.state[i] = _mm256_set1_epi64x(x);
		}

		/* initialize the nonce */
		ctxw.state[12] = _mm256_add_epi64(ctxw.state[12], _mm256_set_epi64x(0, 1, 2, 3));

		/* process 8 blocks in parallel (uses avx512 if available) */
		while (length >= CSX_AVX2_BLOCK)
		{
			csx_permute_p4x1024h(&ctxw);

			for (i = 0; i < 16; ++i)
			{
				tmpin = csx_load256(input + oft + (i * 8));
				ctxw.outw[i] = _mm256_xor_si256(ctxw.outw[i], tmpin);
				csx_store256((output + oft + (i * 8)), ctxw.outw[i]);
			}

			leincrement_256(&ctxw.state[12]);
			oft += CSX_AVX2_BLOCK;
			length -= CSX_AVX2_BLOCK;
		}

		QSC_ALIGN(32) uint8_t ctrblk[32];
		/* store the nonce */
		_mm256_storeu_si256((__m256i*)ctrblk, ctxw.state[12]);
		ctx->state[12] = qsc_intutils_le8to64((ctrblk + 24));
		_mm256_storeu_si256((__m256i*)ctrblk, ctxw.state[13]);
		ctx->state[13] = qsc_intutils_le8to64((ctrblk + 24));
	}

#endif

	/* generate remaining blocks */
	while (length >= QSC_CSX_BLOCK_SIZE)
	{
		csx_permute_p1024c(ctx, (output + oft));
		qsc_memutils_xor((output + oft), (input + oft), QSC_CSX_BLOCK_SIZE);
		csx_increment(ctx);
		oft += QSC_CSX_BLOCK_SIZE;
		length -= QSC_CSX_BLOCK_SIZE;
	}

	/* generate unaligned key-stream */
	if (length != 0)
	{
		uint8_t tmp[QSC_CSX_BLOCK_SIZE] = { 0 };
		csx_permute_p1024c(ctx, tmp);
		csx_increment(ctx);
		qsc_memutils_copy((output + oft), tmp, length);
		qsc_memutils_xor((output + oft), (input + oft), length);
	}
}

static void csx_load_key(qsc_csx_state* ctx, const uint8_t* key, const uint8_t* nonce, const uint8_t* code)
{
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_copy((uint8_t*)ctx->state, key, 64);
	qsc_memutils_copy(((uint8_t*)ctx->state + 64), code, 32);
	qsc_memutils_copy(((uint8_t*)ctx->state + 96), nonce, 16);
	qsc_memutils_copy(((uint8_t*)ctx->state + 112), (code + 32), 16);
#else
	ctx->state[0] = qsc_intutils_le8to64(key);
	ctx->state[1] = qsc_intutils_le8to64((key + 8));
	ctx->state[2] = qsc_intutils_le8to64((key + 16));
	ctx->state[3] = qsc_intutils_le8to64((key + 24));
	ctx->state[4] = qsc_intutils_le8to64((key + 32));
	ctx->state[5] = qsc_intutils_le8to64((key + 40));
	ctx->state[6] = qsc_intutils_le8to64((key + 48));
	ctx->state[7] = qsc_intutils_le8to64((key + 56));
	ctx->state[8] = qsc_intutils_le8to64(code);
	ctx->state[9] = qsc_intutils_le8to64((code + 8));
	ctx->state[10] = qsc_intutils_le8to64((code + 16));
	ctx->state[11] = qsc_intutils_le8to64((code + 24));
	ctx->state[12] = qsc_intutils_le8to64(nonce);
	ctx->state[13] = qsc_intutils_le8to64((nonce + 8));
	ctx->state[14] = qsc_intutils_le8to64((code + 32));
	ctx->state[15] = qsc_intutils_le8to64((code + 40));

#endif
}

#if	defined(QSC_CSX_AUTHENTICATED)
static void csx_finalize(qsc_csx_state* ctx, uint8_t* output)
{
	uint8_t ctr[sizeof(uint64_t)] = { 0 };

	qsc_intutils_le64to8(ctr, ctx->counter);
	csx_mac_update(ctx, ctr, sizeof(ctr));

#if defined(QSC_CSX_AUTH_KMACR12)
	/* update the counter */
	qsc_keccak_update(&ctx->kstate, qsc_keccak_rate_512, ctr, sizeof(ctr), QSC_KECCAK_PERMUTATION_MIN_ROUNDS);
	/* finalize the mac and append code to output */
	qsc_keccak_finalize(&ctx->kstate, qsc_keccak_rate_512, output, QSC_CSX_MAC_SIZE, QSC_KECCAK_KMAC_DOMAIN_ID, QSC_KECCAK_PERMUTATION_MIN_ROUNDS);
#else
	/* finalize the mac and append code to output */
	qsc_kmac_finalize(&ctx->kstate, qsc_keccak_rate_512, output, QSC_CSX_MAC_SIZE);
#endif
}
#endif

/* csx common */

void qsc_csx_dispose(qsc_csx_state* ctx)
{
	assert(ctx != NULL);

	/* clear state */
	if (ctx != NULL)
	{
#if defined(QSC_CSX_AUTHENTICATED)
	qsc_keccak_dispose(&ctx->kstate);
#endif

		qsc_intutils_clear64(ctx->state, QSC_CSX_STATE_SIZE);
		ctx->counter = 0;
		ctx->encrypt = false;
	}
}

void qsc_csx_initialize(qsc_csx_state* ctx, const qsc_csx_keyparams* keyparams, bool encryption)
{
	assert(keyparams->nonce != NULL);
	assert(keyparams->key != NULL);
	assert(keyparams->keylen == QSC_CSX_KEY_SIZE);

	ctx->counter = 0;
	ctx->encrypt = encryption;

#if defined(QSC_CSX_AUTHENTICATED)

	qsc_keccak_state kstate;
	uint8_t buf[QSC_KECCAK_512_RATE] = { 0 };
	uint8_t cpk[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t mck[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t nme[CSX_NAME_LENGTH] = { 0 };

	/* load the information string */
	if (keyparams->infolen == 0)
	{
		qsc_memutils_copy(nme, csx_name, CSX_NAME_LENGTH);
	}
	else
	{
		const size_t INFLEN = qsc_intutils_min(keyparams->infolen, CSX_NAME_LENGTH);
		qsc_memutils_copy(nme, keyparams->info, INFLEN);
	}

	/* initialize the cSHAKE generator */
	qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, keyparams->key, keyparams->keylen, nme, sizeof(nme), NULL, 0);

	/* extract the cipher key */
	qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, buf, 1);
	qsc_memutils_copy(cpk, buf, QSC_CSX_KEY_SIZE);
	csx_load_key(ctx, cpk, keyparams->nonce, csx_info);

	/* extract the mac key */
	qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, buf, 1);
	qsc_memutils_copy(mck, buf, sizeof(mck));

	/* initialize the mac generator */
	qsc_memutils_clear((uint8_t*)ctx->kstate.state, sizeof(ctx->kstate.state));

#if defined(QSC_CSX_AUTH_KMACR12)
	qsc_keccak_initialize_state(&ctx->kstate);
	qsc_keccak_absorb_key_custom(&ctx->kstate, qsc_keccak_rate_512, mck, sizeof(mck), NULL, 0, csx_kmacr12_name, CSX_NAME_LENGTH, QSC_KECCAK_PERMUTATION_MIN_ROUNDS);
#else
	qsc_kmac_initialize(&ctx->kstate, qsc_keccak_rate_512, mck, sizeof(mck), NULL, 0);
#endif

#else

	uint8_t inf[QSC_CSX_INFO_SIZE] = { 0 };

	/* load the information string */
	if (keyparams->infolen == 0)
	{
		qsc_memutils_copy(inf, csx_info, QSC_CSX_INFO_SIZE);
}
	else
	{
		const size_t INFLEN = qsc_intutils_min(keyparams->infolen, QSC_CSX_INFO_SIZE);
		qsc_memutils_copy(inf, keyparams->info, INFLEN);
	}

	qsc_memutils_clear((uint8_t*)ctx->state, sizeof(ctx->state));
	csx_load_key(ctx, keyparams->key, keyparams->nonce, inf);

#endif
}

void qsc_csx_set_associated(qsc_csx_state* ctx, const uint8_t* data, size_t length)
{
	assert(ctx != NULL);
	assert(data != NULL);
	assert(length != 0);

	if (data != NULL && length != 0)
	{
		uint8_t code[sizeof(uint32_t)] = { 0 };

		/* add the ad data to the hash */
		csx_mac_update(ctx, data, length);
		/* add the length of the ad */
		qsc_intutils_le32to8(code, (uint32_t)length);
		csx_mac_update(ctx, code, sizeof(code));
	}
}

bool qsc_csx_transform(qsc_csx_state* ctx, uint8_t* output, const uint8_t* input, size_t length)
{
	assert(ctx != NULL);
	assert(output != NULL);
	assert(input != NULL);

	bool res;

#if defined(QSC_CSX_AUTHENTICATED)

	uint8_t ncopy[QSC_CSX_NONCE_SIZE] = { 0 };
	res = false;

	/* store the nonce */
	qsc_intutils_le64to8(ncopy, ctx->state[12]);
	qsc_intutils_le64to8(ncopy + sizeof(uint64_t), ctx->state[13]);

	/* update the processed bytes counter */
	ctx->counter += length;

	/* update the mac with the nonce */
	csx_mac_update(ctx, ncopy, sizeof(ncopy));

	if (ctx->encrypt)
	{
		/* use the transform to generate the key-stream and encrypt the data  */
		csx_transform(ctx, output, input, length);

		/* update the mac with the cipher-text */
		csx_mac_update(ctx, output, length);

		/* mac the cipher-text appending the code to the end of the array */
		csx_finalize(ctx, output + length);
		res = true;
	}
	else
	{
		uint8_t code[QSC_CSX_MAC_SIZE] = { 0 };

		/* update the mac with the cipher-text */
		csx_mac_update(ctx, input, length);

		/* generate the internal mac code */
		csx_finalize(ctx, code);

		/* compare the mac code with the one embedded in the cipher-text, bypassing the transform if the mac check fails */
		if (qsc_intutils_verify(code, input + length, QSC_CSX_MAC_SIZE) == 0)
		{
			/* generate the key-stream and decrypt the array */
			csx_transform(ctx, output, input, length);
			res = true;
		}
	}

#else

	csx_transform(ctx, output, input, length);
	res = true;

#endif

	return res;
}
