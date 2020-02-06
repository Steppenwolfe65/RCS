#include "sha2.h"
#include "intutils.h"
#include "intrinsics.h"

/* SHA2-256 */

static const uint32_t sha256_iv[8] =
{
	0x6A09E667UL,
	0xBB67AE85UL,
	0x3C6EF372UL,
	0xA54FF53AUL,
	0x510E527FUL,
	0x9B05688CUL,
	0x1F83D9ABUL,
	0x5BE0CD19UL
};

static sha256_increase(sha256_state* state, size_t msglen)
{
	state->t += msglen;
}

void sha256_blockupdate(sha256_state* state, const uint8_t* message, size_t nblocks)
{
	size_t i;

	for (i = 0; i < nblocks; ++i)
	{
		sha256_permute(state->state, message + (i * SHA2_256_RATE));
		sha256_increase(state, SHA2_256_RATE);
	}
}

void sha2_compute256(uint8_t* output, const uint8_t* message, size_t msglen)
{
	sha256_state state;
	size_t blocks;

	sha256_initialize(&state);
	blocks = msglen / SHA2_256_RATE;

	if (msglen >= SHA2_256_RATE)
	{
		sha256_blockupdate(&state, message, blocks);
		msglen -= blocks * SHA2_256_RATE;
	}

	sha256_finalize(&state, output, message + (blocks * SHA2_256_RATE), msglen);
}

void sha256_finalize(sha256_state* state, uint8_t* output, const uint8_t* message, size_t msglen)
{
	uint8_t pad[SHA2_256_RATE] = { 0 };
	uint64_t bitLen;
	size_t i;

	for (i = 0; i < msglen; ++i)
	{
		pad[i] = message[i];
	}

	sha256_increase(state, msglen);
	bitLen = (state->t << 3);

	if (msglen == SHA2_256_RATE)
	{
		sha256_permute(state->state, pad);
		msglen = 0;
	}

	pad[msglen] = 128;
	++msglen;

	/* padding */
	if (msglen < SHA2_256_RATE)
	{
		clear8(pad + msglen, SHA2_256_RATE - msglen);
	}

	if (msglen > 56)
	{
		sha256_permute(state->state, pad);
		clear8(pad, SHA2_256_RATE);
	}

	/* finalize state with counter and last compression */
	be32to8(pad + 56, (uint32_t)(bitLen >> 32));
	be32to8(pad + 60, (uint32_t)bitLen);
	sha256_permute(state->state, pad);

	for (i = 0; i < SHA2_256_HASH; i += 4)
	{
		be32to8(output + i, state->state[i / 4]);
	}
}

void sha256_initialize(sha256_state* state)
{
	size_t i;

	for (i = 0; i < SHA2_STATE_SIZE; ++i)
	{
		state->state[i] = sha256_iv[i];
	}

	state->t = 0;
}

#ifdef SHA2_SHANI_ENABLED
void sha256_permute(uint32_t* output, const uint8_t* message)
{
	__m128i s0;
	__m128i s1;
	__m128i t0;
	__m128i t1;
	__m128i pmsg;
	__m128i m0;
	__m128i m1;
	__m128i m2;
	__m128i m3;
	__m128i mask;
	__m128i ptmp;

	/* load initial values */
	ptmp = _mm_loadu_si128((__m128i*)output);
	s1 = _mm_loadu_si128((__m128i*)output + (4 * sizeof(uint32_t)));
	mask = _mm_set_epi64x(0x0C0D0E0F08090A0BULL, 0x0405060700010203ULL);
	ptmp = _mm_shuffle_epi32(ptmp, 0xB1); 
	s1 = _mm_shuffle_epi32(s1, 0x1B);
	s0 = _mm_alignr_epi8(ptmp, s1, 8);
	s1 = _mm_blend_epi16(s1, ptmp, 0xF0);
	t0 = s0;
	t1 = s1;

	/* rounds 0-3 */
	pmsg = _mm_loadu_si128((const __m128i*)message);
	m0 = _mm_shuffle_epi8(pmsg, mask);
	pmsg = _mm_add_epi32(m0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	/* rounds 4-7 */
	m1 = _mm_loadu_si128((const __m128i*)message + 16);
	m1 = _mm_shuffle_epi8(m1, mask);
	pmsg = _mm_add_epi32(m1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m0 = _mm_sha256msg1_epu32(m0, m1);
	/* rounds 8-11 */
	m2 = _mm_loadu_si128((const __m128i*)message + 32);
	m2 = _mm_shuffle_epi8(m2, mask);
	pmsg = _mm_add_epi32(m2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m1 = _mm_sha256msg1_epu32(m1, m2);
	/* rounds 12-15 */
	m3 = _mm_loadu_si128((const __m128i*)message + 48);
	m3 = _mm_shuffle_epi8(m3, mask);
	pmsg = _mm_add_epi32(m3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m3, m2, 4);
	m0 = _mm_add_epi32(m0, ptmp);
	m0 = _mm_sha256msg2_epu32(m0, m3);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m2 = _mm_sha256msg1_epu32(m2, m3);
	/* rounds 16-19 */
	pmsg = _mm_add_epi32(m0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m0, m3, 4);
	m1 = _mm_add_epi32(m1, ptmp);
	m1 = _mm_sha256msg2_epu32(m1, m0);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m3 = _mm_sha256msg1_epu32(m3, m0);
	/* rounds 20-23 */
	pmsg = _mm_add_epi32(m1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m1, m0, 4);
	m2 = _mm_add_epi32(m2, ptmp);
	m2 = _mm_sha256msg2_epu32(m2, m1);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m0 = _mm_sha256msg1_epu32(m0, m1);
	/* rounds 24-27 */
	pmsg = _mm_add_epi32(m2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m2, m1, 4);
	m3 = _mm_add_epi32(m3, ptmp);
	m3 = _mm_sha256msg2_epu32(m3, m2);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m1 = _mm_sha256msg1_epu32(m1, m2);
	/* rounds 28-31 */
	pmsg = _mm_add_epi32(m3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m3, m2, 4);
	m0 = _mm_add_epi32(m0, ptmp);
	m0 = _mm_sha256msg2_epu32(m0, m3);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m2 = _mm_sha256msg1_epu32(m2, m3);
	/* rounds 32-35 */
	pmsg = _mm_add_epi32(m0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m0, m3, 4);
	m1 = _mm_add_epi32(m1, ptmp);
	m1 = _mm_sha256msg2_epu32(m1, m0);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m3 = _mm_sha256msg1_epu32(m3, m0);
	/* rounds 36-39 */
	pmsg = _mm_add_epi32(m1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m1, m0, 4);
	m2 = _mm_add_epi32(m2, ptmp);
	m2 = _mm_sha256msg2_epu32(m2, m1);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m0 = _mm_sha256msg1_epu32(m0, m1);
	/* rounds 40-43 */
	pmsg = _mm_add_epi32(m2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m2, m1, 4);
	m3 = _mm_add_epi32(m3, ptmp);
	m3 = _mm_sha256msg2_epu32(m3, m2);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m1 = _mm_sha256msg1_epu32(m1, m2);
	/* rounds 44-47 */
	pmsg = _mm_add_epi32(m3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m3, m2, 4);
	m0 = _mm_add_epi32(m0, ptmp);
	m0 = _mm_sha256msg2_epu32(m0, m3);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m2 = _mm_sha256msg1_epu32(m2, m3);
	/* rounds 48-51 */
	pmsg = _mm_add_epi32(m0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m0, m3, 4);
	m1 = _mm_add_epi32(m1, ptmp);
	m1 = _mm_sha256msg2_epu32(m1, m0);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	m3 = _mm_sha256msg1_epu32(m3, m0);
	/* rounds 52-55 */
	pmsg = _mm_add_epi32(m1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m1, m0, 4);
	m2 = _mm_add_epi32(m2, ptmp);
	m2 = _mm_sha256msg2_epu32(m2, m1);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	/* rounds 56-59 */
	pmsg = _mm_add_epi32(m2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	ptmp = _mm_alignr_epi8(m2, m1, 4);
	m3 = _mm_add_epi32(m3, ptmp);
	m3 = _mm_sha256msg2_epu32(m3, m2);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);
	/* rounds 60-63 */
	pmsg = _mm_add_epi32(m3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
	s1 = _mm_sha256rnds2_epu32(s1, s0, pmsg);
	pmsg = _mm_shuffle_epi32(pmsg, 0x0E);
	s0 = _mm_sha256rnds2_epu32(s0, s1, pmsg);

	/* combine state */
	s0 = _mm_add_epi32(s0, t0);
	s1 = _mm_add_epi32(s1, t1);
	ptmp = _mm_shuffle_epi32(s0, 0x1B);
	s1 = _mm_shuffle_epi32(s1, 0xB1);
	s0 = _mm_blend_epi16(ptmp, s1, 0xF0);
	s1 = _mm_alignr_epi8(s1, ptmp, 8);

	/* store */
	_mm_storeu_si128((__m128i*)output, s0);
	_mm_storeu_si128((__m128i*)output + (4 * sizeof(uint32_t)), s1);
}
#else
void sha256_permute(uint32_t* output, const uint8_t* message)
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;
	uint32_t f;
	uint32_t g;
	uint32_t h;
	uint32_t r;
	uint32_t w0;
	uint32_t w1;
	uint32_t w2;
	uint32_t w3;
	uint32_t w4;
	uint32_t w5;
	uint32_t w6;
	uint32_t w7;
	uint32_t w8;
	uint32_t w9;
	uint32_t w10;
	uint32_t w11;
	uint32_t w12;
	uint32_t w13;
	uint32_t w14;
	uint32_t w15;

	a = output[0];
	b = output[1];
	c = output[2];
	d = output[3];
	e = output[4];
	f = output[5];
	g = output[6];
	h = output[7];

	w0 = be8to32(message);
	w1 = be8to32(message + 4);
	w2 = be8to32(message + 8);
	w3 = be8to32(message + 12);
	w4 = be8to32(message + 16);
	w5 = be8to32(message + 20);
	w6 = be8to32(message + 24);
	w7 = be8to32(message + 28);
	w8 = be8to32(message + 32);
	w9 = be8to32(message + 36);
	w10 = be8to32(message + 40);
	w11 = be8to32(message + 44);
	w12 = be8to32(message + 48);
	w13 = be8to32(message + 52);
	w14 = be8to32(message + 56);
	w15 = be8to32(message + 60);

	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w0 + 0x428a2f98UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w1 + 0x71374491UL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w2 + 0xb5c0fbcfUL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w3 + 0xe9b5dba5UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w4 + 0x3956c25bUL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w5 + 0x59f111f1UL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w6 + 0x923f82a4UL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w7 + 0xab1c5ed5UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w8 + 0xd807aa98UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w9 + 0x12835b01UL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w10 + 0x243185beUL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w11 + 0x550c7dc3UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w12 + 0x72be5d74UL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w13 + 0x80deb1feUL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w14 + 0x9bdc06a7UL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w15 + 0xc19bf174UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));

	w0 += (((w14 >> 17) | (w14 << 15)) ^ ((w14 >> 19) | (w14 << 13)) ^ (w14 >> 10)) + w9 + (((w1 >> 7) | (w1 << 25)) ^ ((w1 >> 18) | (w1 << 14)) ^ (w1 >> 3));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w0 + 0xe49b69c1UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	w1 += (((w15 >> 17) | (w15 << 15)) ^ ((w15 >> 19) | (w15 << 13)) ^ (w15 >> 10)) + w10 + (((w2 >> 7) | (w2 << 25)) ^ ((w2 >> 18) | (w2 << 14)) ^ (w2 >> 3));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w1 + 0xefbe4786UL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	w2 += (((w0 >> 17) | (w0 << 15)) ^ ((w0 >> 19) | (w0 << 13)) ^ (w0 >> 10)) + w11 + (((w3 >> 7) | (w3 << 25)) ^ ((w3 >> 18) | (w3 << 14)) ^ (w3 >> 3));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w2 + 0x0fc19dc6UL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	w3 += (((w1 >> 17) | (w1 << 15)) ^ ((w1 >> 19) | (w1 << 13)) ^ (w1 >> 10)) + w12 + (((w4 >> 7) | (w4 << 25)) ^ ((w4 >> 18) | (w4 << 14)) ^ (w4 >> 3));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w3 + 0x240ca1ccUL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	w4 += (((w2 >> 17) | (w2 << 15)) ^ ((w2 >> 19) | (w2 << 13)) ^ (w2 >> 10)) + w13 + (((w5 >> 7) | (w5 << 25)) ^ ((w5 >> 18) | (w5 << 14)) ^ (w5 >> 3));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w4 + 0x2de92c6fUL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	w5 += (((w3 >> 17) | (w3 << 15)) ^ ((w3 >> 19) | (w3 << 13)) ^ (w3 >> 10)) + w14 + (((w6 >> 7) | (w6 << 25)) ^ ((w6 >> 18) | (w6 << 14)) ^ (w6 >> 3));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w5 + 0x4a7484aaUL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	w6 += (((w4 >> 17) | (w4 << 15)) ^ ((w4 >> 19) | (w4 << 13)) ^ (w4 >> 10)) + w15 + (((w7 >> 7) | (w7 << 25)) ^ ((w7 >> 18) | (w7 << 14)) ^ (w7 >> 3));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w6 + 0x5cb0a9dcUL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	w7 += (((w5 >> 17) | (w5 << 15)) ^ ((w5 >> 19) | (w5 << 13)) ^ (w5 >> 10)) + w0 + (((w8 >> 7) | (w8 << 25)) ^ ((w8 >> 18) | (w8 << 14)) ^ (w8 >> 3));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w7 + 0x76f988daUL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));
	w8 += (((w6 >> 17) | (w6 << 15)) ^ ((w6 >> 19) | (w6 << 13)) ^ (w6 >> 10)) + w1 + (((w9 >> 7) | (w9 << 25)) ^ ((w9 >> 18) | (w9 << 14)) ^ (w9 >> 3));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w8 + 0x983e5152UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	w9 += (((w7 >> 17) | (w7 << 15)) ^ ((w7 >> 19) | (w7 << 13)) ^ (w7 >> 10)) + w2 + (((w10 >> 7) | (w10 << 25)) ^ ((w10 >> 18) | (w10 << 14)) ^ (w10 >> 3));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w9 + 0xa831c66dUL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	w10 += (((w8 >> 17) | (w8 << 15)) ^ ((w8 >> 19) | (w8 << 13)) ^ (w8 >> 10)) + w3 + (((w11 >> 7) | (w11 << 25)) ^ ((w11 >> 18) | (w11 << 14)) ^ (w11 >> 3));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w10 + 0xb00327c8UL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	w11 += (((w9 >> 17) | (w9 << 15)) ^ ((w9 >> 19) | (w9 << 13)) ^ (w9 >> 10)) + w4 + (((w12 >> 7) | (w12 << 25)) ^ ((w12 >> 18) | (w12 << 14)) ^ (w12 >> 3));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w11 + 0xbf597fc7UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	w12 += (((w10 >> 17) | (w10 << 15)) ^ ((w10 >> 19) | (w10 << 13)) ^ (w10 >> 10)) + w5 + (((w13 >> 7) | (w13 << 25)) ^ ((w13 >> 18) | (w13 << 14)) ^ (w13 >> 3));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w12 + 0xc6e00bf3UL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	w13 += (((w11 >> 17) | (w11 << 15)) ^ ((w11 >> 19) | (w11 << 13)) ^ (w11 >> 10)) + w6 + (((w14 >> 7) | (w14 << 25)) ^ ((w14 >> 18) | (w14 << 14)) ^ (w14 >> 3));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w13 + 0xd5a79147UL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	w14 += (((w12 >> 17) | (w12 << 15)) ^ ((w12 >> 19) | (w12 << 13)) ^ (w12 >> 10)) + w7 + (((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w14 + 0x06ca6351UL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	w15 += (((w13 >> 17) | (w13 << 15)) ^ ((w13 >> 19) | (w13 << 13)) ^ (w13 >> 10)) + w8 + (((w0 >> 7) | (w0 << 25)) ^ ((w0 >> 18) | (w0 << 14)) ^ (w0 >> 3));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w15 + 0x14292967UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));

	w0 += (((w14 >> 17) | (w14 << 15)) ^ ((w14 >> 19) | (w14 << 13)) ^ (w14 >> 10)) + w9 + (((w1 >> 7) | (w1 << 25)) ^ ((w1 >> 18) | (w1 << 14)) ^ (w1 >> 3));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w0 + 0x27b70a85UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	w1 += (((w15 >> 17) | (w15 << 15)) ^ ((w15 >> 19) | (w15 << 13)) ^ (w15 >> 10)) + w10 + (((w2 >> 7) | (w2 << 25)) ^ ((w2 >> 18) | (w2 << 14)) ^ (w2 >> 3));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w1 + 0x2e1b2138UL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	w2 += (((w0 >> 17) | (w0 << 15)) ^ ((w0 >> 19) | (w0 << 13)) ^ (w0 >> 10)) + w11 + (((w3 >> 7) | (w3 << 25)) ^ ((w3 >> 18) | (w3 << 14)) ^ (w3 >> 3));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w2 + 0x4d2c6dfcUL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	w3 += (((w1 >> 17) | (w1 << 15)) ^ ((w1 >> 19) | (w1 << 13)) ^ (w1 >> 10)) + w12 + (((w4 >> 7) | (w4 << 25)) ^ ((w4 >> 18) | (w4 << 14)) ^ (w4 >> 3));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w3 + 0x53380d13UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	w4 += (((w2 >> 17) | (w2 << 15)) ^ ((w2 >> 19) | (w2 << 13)) ^ (w2 >> 10)) + w13 + (((w5 >> 7) | (w5 << 25)) ^ ((w5 >> 18) | (w5 << 14)) ^ (w5 >> 3));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w4 + 0x650a7354UL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	w5 += (((w3 >> 17) | (w3 << 15)) ^ ((w3 >> 19) | (w3 << 13)) ^ (w3 >> 10)) + w14 + (((w6 >> 7) | (w6 << 25)) ^ ((w6 >> 18) | (w6 << 14)) ^ (w6 >> 3));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w5 + 0x766a0abbUL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	w6 += (((w4 >> 17) | (w4 << 15)) ^ ((w4 >> 19) | (w4 << 13)) ^ (w4 >> 10)) + w15 + (((w7 >> 7) | (w7 << 25)) ^ ((w7 >> 18) | (w7 << 14)) ^ (w7 >> 3));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w6 + 0x81c2c92eUL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	w7 += (((w5 >> 17) | (w5 << 15)) ^ ((w5 >> 19) | (w5 << 13)) ^ (w5 >> 10)) + w0 + (((w8 >> 7) | (w8 << 25)) ^ ((w8 >> 18) | (w8 << 14)) ^ (w8 >> 3));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w7 + 0x92722c85UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));
	w8 += (((w6 >> 17) | (w6 << 15)) ^ ((w6 >> 19) | (w6 << 13)) ^ (w6 >> 10)) + w1 + (((w9 >> 7) | (w9 << 25)) ^ ((w9 >> 18) | (w9 << 14)) ^ (w9 >> 3));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w8 + 0xa2bfe8a1UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	w9 += (((w7 >> 17) | (w7 << 15)) ^ ((w7 >> 19) | (w7 << 13)) ^ (w7 >> 10)) + w2 + (((w10 >> 7) | (w10 << 25)) ^ ((w10 >> 18) | (w10 << 14)) ^ (w10 >> 3));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w9 + 0xa81a664bUL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	w10 += (((w8 >> 17) | (w8 << 15)) ^ ((w8 >> 19) | (w8 << 13)) ^ (w8 >> 10)) + w3 + (((w11 >> 7) | (w11 << 25)) ^ ((w11 >> 18) | (w11 << 14)) ^ (w11 >> 3));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w10 + 0xc24b8b70UL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	w11 += (((w9 >> 17) | (w9 << 15)) ^ ((w9 >> 19) | (w9 << 13)) ^ (w9 >> 10)) + w4 + (((w12 >> 7) | (w12 << 25)) ^ ((w12 >> 18) | (w12 << 14)) ^ (w12 >> 3));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w11 + 0xc76c51a3UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	w12 += (((w10 >> 17) | (w10 << 15)) ^ ((w10 >> 19) | (w10 << 13)) ^ (w10 >> 10)) + w5 + (((w13 >> 7) | (w13 << 25)) ^ ((w13 >> 18) | (w13 << 14)) ^ (w13 >> 3));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w12 + 0xd192e819UL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	w13 += (((w11 >> 17) | (w11 << 15)) ^ ((w11 >> 19) | (w11 << 13)) ^ (w11 >> 10)) + w6 + (((w14 >> 7) | (w14 << 25)) ^ ((w14 >> 18) | (w14 << 14)) ^ (w14 >> 3));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w13 + 0xd6990624UL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	w14 += (((w12 >> 17) | (w12 << 15)) ^ ((w12 >> 19) | (w12 << 13)) ^ (w12 >> 10)) + w7 + (((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w14 + 0xf40e3585UL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	w15 += (((w13 >> 17) | (w13 << 15)) ^ ((w13 >> 19) | (w13 << 13)) ^ (w13 >> 10)) + w8 + (((w0 >> 7) | (w0 << 25)) ^ ((w0 >> 18) | (w0 << 14)) ^ (w0 >> 3));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w15 + 0x106aa070UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));

	w0 += (((w14 >> 17) | (w14 << 15)) ^ ((w14 >> 19) | (w14 << 13)) ^ (w14 >> 10)) + w9 + (((w1 >> 7) | (w1 << 25)) ^ ((w1 >> 18) | (w1 << 14)) ^ (w1 >> 3));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w0 + 0x19a4c116UL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	w1 += (((w15 >> 17) | (w15 << 15)) ^ ((w15 >> 19) | (w15 << 13)) ^ (w15 >> 10)) + w10 + (((w2 >> 7) | (w2 << 25)) ^ ((w2 >> 18) | (w2 << 14)) ^ (w2 >> 3));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w1 + 0x1e376c08UL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	w2 += (((w0 >> 17) | (w0 << 15)) ^ ((w0 >> 19) | (w0 << 13)) ^ (w0 >> 10)) + w11 + (((w3 >> 7) | (w3 << 25)) ^ ((w3 >> 18) | (w3 << 14)) ^ (w3 >> 3));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w2 + 0x2748774cUL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	w3 += (((w1 >> 17) | (w1 << 15)) ^ ((w1 >> 19) | (w1 << 13)) ^ (w1 >> 10)) + w12 + (((w4 >> 7) | (w4 << 25)) ^ ((w4 >> 18) | (w4 << 14)) ^ (w4 >> 3));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w3 + 0x34b0bcb5UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	w4 += (((w2 >> 17) | (w2 << 15)) ^ ((w2 >> 19) | (w2 << 13)) ^ (w2 >> 10)) + w13 + (((w5 >> 7) | (w5 << 25)) ^ ((w5 >> 18) | (w5 << 14)) ^ (w5 >> 3));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w4 + 0x391c0cb3UL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	w5 += (((w3 >> 17) | (w3 << 15)) ^ ((w3 >> 19) | (w3 << 13)) ^ (w3 >> 10)) + w14 + (((w6 >> 7) | (w6 << 25)) ^ ((w6 >> 18) | (w6 << 14)) ^ (w6 >> 3));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w5 + 0x4ed8aa4aUL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	w6 += (((w4 >> 17) | (w4 << 15)) ^ ((w4 >> 19) | (w4 << 13)) ^ (w4 >> 10)) + w15 + (((w7 >> 7) | (w7 << 25)) ^ ((w7 >> 18) | (w7 << 14)) ^ (w7 >> 3));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w6 + 0x5b9cca4fUL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	w7 += (((w5 >> 17) | (w5 << 15)) ^ ((w5 >> 19) | (w5 << 13)) ^ (w5 >> 10)) + w0 + (((w8 >> 7) | (w8 << 25)) ^ ((w8 >> 18) | (w8 << 14)) ^ (w8 >> 3));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w7 + 0x682e6ff3UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));
	w8 += (((w6 >> 17) | (w6 << 15)) ^ ((w6 >> 19) | (w6 << 13)) ^ (w6 >> 10)) + w1 + (((w9 >> 7) | (w9 << 25)) ^ ((w9 >> 18) | (w9 << 14)) ^ (w9 >> 3));
	r = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + w8 + 0x748f82eeUL;
	d += r;
	h = r + ((((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c)));
	w9 += (((w7 >> 17) | (w7 << 15)) ^ ((w7 >> 19) | (w7 << 13)) ^ (w7 >> 10)) + w2 + (((w10 >> 7) | (w10 << 25)) ^ ((w10 >> 18) | (w10 << 14)) ^ (w10 >> 3));
	r = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + w9 + 0x78a5636fUL;
	c += r;
	g = r + ((((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b)));
	w10 += (((w8 >> 17) | (w8 << 15)) ^ ((w8 >> 19) | (w8 << 13)) ^ (w8 >> 10)) + w3 + (((w11 >> 7) | (w11 << 25)) ^ ((w11 >> 18) | (w11 << 14)) ^ (w11 >> 3));
	r = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + w10 + 0x84c87814UL;
	b += r;
	f = r + ((((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a)));
	w11 += (((w9 >> 17) | (w9 << 15)) ^ ((w9 >> 19) | (w9 << 13)) ^ (w9 >> 10)) + w4 + (((w12 >> 7) | (w12 << 25)) ^ ((w12 >> 18) | (w12 << 14)) ^ (w12 >> 3));
	r = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + w11 + 0x8cc70208UL;
	a += r;
	e = r + ((((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h)));
	w12 += (((w10 >> 17) | (w10 << 15)) ^ ((w10 >> 19) | (w10 << 13)) ^ (w10 >> 10)) + w5 + (((w13 >> 7) | (w13 << 25)) ^ ((w13 >> 18) | (w13 << 14)) ^ (w13 >> 3));
	r = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + w12 + 0x90befffaUL;
	h += r;
	d = r + ((((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g)));
	w13 += (((w11 >> 17) | (w11 << 15)) ^ ((w11 >> 19) | (w11 << 13)) ^ (w11 >> 10)) + w6 + (((w14 >> 7) | (w14 << 25)) ^ ((w14 >> 18) | (w14 << 14)) ^ (w14 >> 3));
	r = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + w13 + 0xa4506cebUL;
	g += r;
	c = r + ((((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f)));
	w14 += (((w12 >> 17) | (w12 << 15)) ^ ((w12 >> 19) | (w12 << 13)) ^ (w12 >> 10)) + w7 + (((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3));
	r = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + w14 + 0xbef9a3f7UL;
	f += r;
	b = r + ((((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e)));
	w15 += (((w13 >> 17) | (w13 << 15)) ^ ((w13 >> 19) | (w13 << 13)) ^ (w13 >> 10)) + w8 + (((w0 >> 7) | (w0 << 25)) ^ ((w0 >> 18) | (w0 << 14)) ^ (w0 >> 3));
	r = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + w15 + 0xc67178f2UL;
	e += r;
	a = r + ((((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d)));

	output[0] += a;
	output[1] += b;
	output[2] += c;
	output[3] += d;
	output[4] += e;
	output[5] += f;
	output[6] += g;
	output[7] += h;
}
#endif

/* SHA2-384 */

static const uint64_t sha384_iv[8] =
{
	0xCBBB9D5DC1059ED8ULL,
	0x629A292A367CD507ULL,
	0x9159015A3070DD17ULL,
	0x152FECD8F70E5939ULL,
	0x67332667FFC00B31ULL,
	0x8EB44A8768581511ULL,
	0xDB0C2E0D64F98FA7ULL,
	0x47B5481DBEFA4FA4ULL
};

static void sha384_increase(sha384_state* state, size_t length)
{
	state->t[0] += length;

	if (state->t[0] > 0x1FFFFFFFFFFFFFFFULL)
	{
		state->t[1] += (uint64_t)(state->t[0] >> 61);
		state->t[0] &= 0x1FFFFFFFFFFFFFFFULL;
	}
}

void sha2_compute384(uint8_t* output, const uint8_t* message, size_t msglen)
{
	sha384_state state;
	size_t blocks;

	sha384_initialize(&state);
	blocks = msglen / SHA2_384_RATE;

	if (msglen >= SHA2_384_RATE)
	{
		sha384_blockupdate(&state, message, blocks);
		msglen -= blocks * SHA2_384_RATE;
	}

	sha384_finalize(&state, output, message + (blocks * SHA2_384_RATE), msglen);
}

void sha384_blockupdate(sha384_state* state, const uint8_t* message, size_t nblocks)
{
	size_t i;

	for (i = 0; i < nblocks; ++i)
	{
		sha384_permute(state->state, message + (i * SHA2_384_RATE));
		sha384_increase(state, SHA2_384_RATE);
	}
}

void sha384_finalize(sha384_state* state, uint8_t* output, const uint8_t* message, size_t msglen)
{
	uint8_t pad[SHA2_384_RATE] = { 0 };
	uint64_t bitLen;
	size_t i;

	sha384_increase(state, msglen);
	bitLen = (state->t[0] << 3);

	for (i = 0; i < msglen; ++i)
	{
		pad[i] = message[i];
	}

	if (msglen == SHA2_384_RATE)
	{
		sha384_permute(state->state, pad);
		msglen = 0;
	}

	pad[msglen] = 128;
	++msglen;

	/* padding */
	if (msglen < SHA2_384_RATE)
	{
		clear8(pad + msglen, SHA2_384_RATE - msglen);
	}

	if (msglen > 112)
	{
		sha384_permute(state->state, pad);
		clear8(pad, SHA2_384_RATE);
	}

	/* finalize state with counter and last compression */
	be64to8(pad + 112, state->t[1]);
	be64to8(pad + 120, bitLen);
	sha384_permute(state->state, pad);

	for (i = 0; i < SHA2_384_HASH; i += 8)
	{
		be64to8(output + i, state->state[i / 8]);
	}
}

void sha384_initialize(sha384_state* state)
{
	size_t i;

	for (i = 0; i < SHA2_STATE_SIZE; ++i)
	{
		state->state[i] = sha384_iv[i];
	}

	state->t[0] = 0;
	state->t[1] = 0;
}

void sha384_permute(uint64_t* output, const uint8_t* message)
{
	uint64_t a;
	uint64_t b;
	uint64_t c;
	uint64_t d;
	uint64_t e;
	uint64_t f;
	uint64_t g;
	uint64_t h;
	uint64_t r;
	uint64_t w0;
	uint64_t w1;
	uint64_t w2;
	uint64_t w3;
	uint64_t w4;
	uint64_t w5;
	uint64_t w6;
	uint64_t w7;
	uint64_t w8;
	uint64_t w9;
	uint64_t w10;
	uint64_t w11;
	uint64_t w12;
	uint64_t w13;
	uint64_t w14;
	uint64_t w15;

	a = output[0];
	b = output[1];
	c = output[2];
	d = output[3];
	e = output[4];
	f = output[5];
	g = output[6];
	h = output[7];

	w0 = be8to64(message);
	w1 = be8to64(message + 8);
	w2 = be8to64(message + 16);
	w3 = be8to64(message + 24);
	w4 = be8to64(message + 32);
	w5 = be8to64(message + 40);
	w6 = be8to64(message + 48);
	w7 = be8to64(message + 56);
	w8 = be8to64(message + 64);
	w9 = be8to64(message + 72);
	w10 = be8to64(message + 80);
	w11 = be8to64(message + 88);
	w12 = be8to64(message + 96);
	w13 = be8to64(message + 104);
	w14 = be8to64(message + 112);
	w15 = be8to64(message + 120);

	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0x428a2f98d728ae22ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0x7137449123ef65cdULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0xb5c0fbcfec4d3b2fULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0xe9b5dba58189dbbcULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x3956c25bf348b538ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x59f111f1b605d019ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x923f82a4af194f9bULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0xab1c5ed5da6d8118ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0xd807aa98a3030242ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0x12835b0145706fbeULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0x243185be4ee4b28cULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0x550c7dc3d5ffb4e2ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0x72be5d74f27b896fULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0x80deb1fe3b1696b1ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0x9bdc06a725c71235ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0xc19bf174cf692694ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	w0 += (((w14 << 45) | (w14 >> 19)) ^ ((w14 << 3) | (w14 >> 61)) ^ (w14 >> 6)) + w9 + (((w1 << 63) | (w1 >> 1)) ^ ((w1 << 56) | (w1 >> 8)) ^ (w1 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0xe49b69c19ef14ad2ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w1 += (((w15 << 45) | (w15 >> 19)) ^ ((w15 << 3) | (w15 >> 61)) ^ (w15 >> 6)) + w10 + (((w2 << 63) | (w2 >> 1)) ^ ((w2 << 56) | (w2 >> 8)) ^ (w2 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0xefbe4786384f25e3ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w2 += (((w0 << 45) | (w0 >> 19)) ^ ((w0 << 3) | (w0 >> 61)) ^ (w0 >> 6)) + w11 + (((w3 << 63) | (w3 >> 1)) ^ ((w3 << 56) | (w3 >> 8)) ^ (w3 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0x0fc19dc68b8cd5b5ULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w3 += (((w1 << 45) | (w1 >> 19)) ^ ((w1 << 3) | (w1 >> 61)) ^ (w1 >> 6)) + w12 + (((w4 << 63) | (w4 >> 1)) ^ ((w4 << 56) | (w4 >> 8)) ^ (w4 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0x240ca1cc77ac9c65ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w4 += (((w2 << 45) | (w2 >> 19)) ^ ((w2 << 3) | (w2 >> 61)) ^ (w2 >> 6)) + w13 + (((w5 << 63) | (w5 >> 1)) ^ ((w5 << 56) | (w5 >> 8)) ^ (w5 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x2de92c6f592b0275ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w5 += (((w3 << 45) | (w3 >> 19)) ^ ((w3 << 3) | (w3 >> 61)) ^ (w3 >> 6)) + w14 + (((w6 << 63) | (w6 >> 1)) ^ ((w6 << 56) | (w6 >> 8)) ^ (w6 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x4a7484aa6ea6e483ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w6 += (((w4 << 45) | (w4 >> 19)) ^ ((w4 << 3) | (w4 >> 61)) ^ (w4 >> 6)) + w15 + (((w7 << 63) | (w7 >> 1)) ^ ((w7 << 56) | (w7 >> 8)) ^ (w7 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x5cb0a9dcbd41fbd4ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w7 += (((w5 << 45) | (w5 >> 19)) ^ ((w5 << 3) | (w5 >> 61)) ^ (w5 >> 6)) + w0 + (((w8 << 63) | (w8 >> 1)) ^ ((w8 << 56) | (w8 >> 8)) ^ (w8 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0x76f988da831153b5ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	w8 += (((w6 << 45) | (w6 >> 19)) ^ ((w6 << 3) | (w6 >> 61)) ^ (w6 >> 6)) + w1 + (((w9 << 63) | (w9 >> 1)) ^ ((w9 << 56) | (w9 >> 8)) ^ (w9 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0x983e5152ee66dfabULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w9 += (((w7 << 45) | (w7 >> 19)) ^ ((w7 << 3) | (w7 >> 61)) ^ (w7 >> 6)) + w2 + (((w10 << 63) | (w10 >> 1)) ^ ((w10 << 56) | (w10 >> 8)) ^ (w10 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0xa831c66d2db43210ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w10 += (((w8 << 45) | (w8 >> 19)) ^ ((w8 << 3) | (w8 >> 61)) ^ (w8 >> 6)) + w3 + (((w11 << 63) | (w11 >> 1)) ^ ((w11 << 56) | (w11 >> 8)) ^ (w11 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0xb00327c898fb213fULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w11 += (((w9 << 45) | (w9 >> 19)) ^ ((w9 << 3) | (w9 >> 61)) ^ (w9 >> 6)) + w4 + (((w12 << 63) | (w12 >> 1)) ^ ((w12 << 56) | (w12 >> 8)) ^ (w12 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0xbf597fc7beef0ee4ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w12 += (((w10 << 45) | (w10 >> 19)) ^ ((w10 << 3) | (w10 >> 61)) ^ (w10 >> 6)) + w5 + (((w13 << 63) | (w13 >> 1)) ^ ((w13 << 56) | (w13 >> 8)) ^ (w13 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0xc6e00bf33da88fc2ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w13 += (((w11 << 45) | (w11 >> 19)) ^ ((w11 << 3) | (w11 >> 61)) ^ (w11 >> 6)) + w6 + (((w14 << 63) | (w14 >> 1)) ^ ((w14 << 56) | (w14 >> 8)) ^ (w14 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0xd5a79147930aa725ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w14 += (((w12 << 45) | (w12 >> 19)) ^ ((w12 << 3) | (w12 >> 61)) ^ (w12 >> 6)) + w7 + (((w15 << 63) | (w15 >> 1)) ^ ((w15 << 56) | (w15 >> 8)) ^ (w15 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0x06ca6351e003826fULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w15 += (((w13 << 45) | (w13 >> 19)) ^ ((w13 << 3) | (w13 >> 61)) ^ (w13 >> 6)) + w8 + (((w0 << 63) | (w0 >> 1)) ^ ((w0 << 56) | (w0 >> 8)) ^ (w0 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0x142929670a0e6e70ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	w0 += (((w14 << 45) | (w14 >> 19)) ^ ((w14 << 3) | (w14 >> 61)) ^ (w14 >> 6)) + w9 + (((w1 << 63) | (w1 >> 1)) ^ ((w1 << 56) | (w1 >> 8)) ^ (w1 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0x27b70a8546d22ffcULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w1 += (((w15 << 45) | (w15 >> 19)) ^ ((w15 << 3) | (w15 >> 61)) ^ (w15 >> 6)) + w10 + (((w2 << 63) | (w2 >> 1)) ^ ((w2 << 56) | (w2 >> 8)) ^ (w2 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0x2e1b21385c26c926ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w2 += (((w0 << 45) | (w0 >> 19)) ^ ((w0 << 3) | (w0 >> 61)) ^ (w0 >> 6)) + w11 + (((w3 << 63) | (w3 >> 1)) ^ ((w3 << 56) | (w3 >> 8)) ^ (w3 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0x4d2c6dfc5ac42aedULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w3 += (((w1 << 45) | (w1 >> 19)) ^ ((w1 << 3) | (w1 >> 61)) ^ (w1 >> 6)) + w12 + (((w4 << 63) | (w4 >> 1)) ^ ((w4 << 56) | (w4 >> 8)) ^ (w4 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0x53380d139d95b3dfULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w4 += (((w2 << 45) | (w2 >> 19)) ^ ((w2 << 3) | (w2 >> 61)) ^ (w2 >> 6)) + w13 + (((w5 << 63) | (w5 >> 1)) ^ ((w5 << 56) | (w5 >> 8)) ^ (w5 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x650a73548baf63deULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w5 += (((w3 << 45) | (w3 >> 19)) ^ ((w3 << 3) | (w3 >> 61)) ^ (w3 >> 6)) + w14 + (((w6 << 63) | (w6 >> 1)) ^ ((w6 << 56) | (w6 >> 8)) ^ (w6 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x766a0abb3c77b2a8ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w6 += (((w4 << 45) | (w4 >> 19)) ^ ((w4 << 3) | (w4 >> 61)) ^ (w4 >> 6)) + w15 + (((w7 << 63) | (w7 >> 1)) ^ ((w7 << 56) | (w7 >> 8)) ^ (w7 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x81c2c92e47edaee6ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w7 += (((w5 << 45) | (w5 >> 19)) ^ ((w5 << 3) | (w5 >> 61)) ^ (w5 >> 6)) + w0 + (((w8 << 63) | (w8 >> 1)) ^ ((w8 << 56) | (w8 >> 8)) ^ (w8 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0x92722c851482353bULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	w8 += (((w6 << 45) | (w6 >> 19)) ^ ((w6 << 3) | (w6 >> 61)) ^ (w6 >> 6)) + w1 + (((w9 << 63) | (w9 >> 1)) ^ ((w9 << 56) | (w9 >> 8)) ^ (w9 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0xa2bfe8a14cf10364ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w9 += (((w7 << 45) | (w7 >> 19)) ^ ((w7 << 3) | (w7 >> 61)) ^ (w7 >> 6)) + w2 + (((w10 << 63) | (w10 >> 1)) ^ ((w10 << 56) | (w10 >> 8)) ^ (w10 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0xa81a664bbc423001ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w10 += (((w8 << 45) | (w8 >> 19)) ^ ((w8 << 3) | (w8 >> 61)) ^ (w8 >> 6)) + w3 + (((w11 << 63) | (w11 >> 1)) ^ ((w11 << 56) | (w11 >> 8)) ^ (w11 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0xc24b8b70d0f89791ULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w11 += (((w9 << 45) | (w9 >> 19)) ^ ((w9 << 3) | (w9 >> 61)) ^ (w9 >> 6)) + w4 + (((w12 << 63) | (w12 >> 1)) ^ ((w12 << 56) | (w12 >> 8)) ^ (w12 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0xc76c51a30654be30ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w12 += (((w10 << 45) | (w10 >> 19)) ^ ((w10 << 3) | (w10 >> 61)) ^ (w10 >> 6)) + w5 + (((w13 << 63) | (w13 >> 1)) ^ ((w13 << 56) | (w13 >> 8)) ^ (w13 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0xd192e819d6ef5218ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w13 += (((w11 << 45) | (w11 >> 19)) ^ ((w11 << 3) | (w11 >> 61)) ^ (w11 >> 6)) + w6 + (((w14 << 63) | (w14 >> 1)) ^ ((w14 << 56) | (w14 >> 8)) ^ (w14 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0xd69906245565a910ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w14 += (((w12 << 45) | (w12 >> 19)) ^ ((w12 << 3) | (w12 >> 61)) ^ (w12 >> 6)) + w7 + (((w15 << 63) | (w15 >> 1)) ^ ((w15 << 56) | (w15 >> 8)) ^ (w15 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0xf40e35855771202aULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w15 += (((w13 << 45) | (w13 >> 19)) ^ ((w13 << 3) | (w13 >> 61)) ^ (w13 >> 6)) + w8 + (((w0 << 63) | (w0 >> 1)) ^ ((w0 << 56) | (w0 >> 8)) ^ (w0 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0x106aa07032bbd1b8ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	w0 += (((w14 << 45) | (w14 >> 19)) ^ ((w14 << 3) | (w14 >> 61)) ^ (w14 >> 6)) + w9 + (((w1 << 63) | (w1 >> 1)) ^ ((w1 << 56) | (w1 >> 8)) ^ (w1 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0x19a4c116b8d2d0c8ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w1 += (((w15 << 45) | (w15 >> 19)) ^ ((w15 << 3) | (w15 >> 61)) ^ (w15 >> 6)) + w10 + (((w2 << 63) | (w2 >> 1)) ^ ((w2 << 56) | (w2 >> 8)) ^ (w2 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0x1e376c085141ab53ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w2 += (((w0 << 45) | (w0 >> 19)) ^ ((w0 << 3) | (w0 >> 61)) ^ (w0 >> 6)) + w11 + (((w3 << 63) | (w3 >> 1)) ^ ((w3 << 56) | (w3 >> 8)) ^ (w3 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0x2748774cdf8eeb99ULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w3 += (((w1 << 45) | (w1 >> 19)) ^ ((w1 << 3) | (w1 >> 61)) ^ (w1 >> 6)) + w12 + (((w4 << 63) | (w4 >> 1)) ^ ((w4 << 56) | (w4 >> 8)) ^ (w4 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0x34b0bcb5e19b48a8ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w4 += (((w2 << 45) | (w2 >> 19)) ^ ((w2 << 3) | (w2 >> 61)) ^ (w2 >> 6)) + w13 + (((w5 << 63) | (w5 >> 1)) ^ ((w5 << 56) | (w5 >> 8)) ^ (w5 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x391c0cb3c5c95a63ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w5 += (((w3 << 45) | (w3 >> 19)) ^ ((w3 << 3) | (w3 >> 61)) ^ (w3 >> 6)) + w14 + (((w6 << 63) | (w6 >> 1)) ^ ((w6 << 56) | (w6 >> 8)) ^ (w6 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x4ed8aa4ae3418acbULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w6 += (((w4 << 45) | (w4 >> 19)) ^ ((w4 << 3) | (w4 >> 61)) ^ (w4 >> 6)) + w15 + (((w7 << 63) | (w7 >> 1)) ^ ((w7 << 56) | (w7 >> 8)) ^ (w7 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x5b9cca4f7763e373ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w7 += (((w5 << 45) | (w5 >> 19)) ^ ((w5 << 3) | (w5 >> 61)) ^ (w5 >> 6)) + w0 + (((w8 << 63) | (w8 >> 1)) ^ ((w8 << 56) | (w8 >> 8)) ^ (w8 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0x682e6ff3d6b2b8a3ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	w8 += (((w6 << 45) | (w6 >> 19)) ^ ((w6 << 3) | (w6 >> 61)) ^ (w6 >> 6)) + w1 + (((w9 << 63) | (w9 >> 1)) ^ ((w9 << 56) | (w9 >> 8)) ^ (w9 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0x748f82ee5defb2fcULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w9 += (((w7 << 45) | (w7 >> 19)) ^ ((w7 << 3) | (w7 >> 61)) ^ (w7 >> 6)) + w2 + (((w10 << 63) | (w10 >> 1)) ^ ((w10 << 56) | (w10 >> 8)) ^ (w10 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0x78a5636f43172f60ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w10 += (((w8 << 45) | (w8 >> 19)) ^ ((w8 << 3) | (w8 >> 61)) ^ (w8 >> 6)) + w3 + (((w11 << 63) | (w11 >> 1)) ^ ((w11 << 56) | (w11 >> 8)) ^ (w11 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0x84c87814a1f0ab72ULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w11 += (((w9 << 45) | (w9 >> 19)) ^ ((w9 << 3) | (w9 >> 61)) ^ (w9 >> 6)) + w4 + (((w12 << 63) | (w12 >> 1)) ^ ((w12 << 56) | (w12 >> 8)) ^ (w12 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0x8cc702081a6439ecULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w12 += (((w10 << 45) | (w10 >> 19)) ^ ((w10 << 3) | (w10 >> 61)) ^ (w10 >> 6)) + w5 + (((w13 << 63) | (w13 >> 1)) ^ ((w13 << 56) | (w13 >> 8)) ^ (w13 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0x90befffa23631e28ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w13 += (((w11 << 45) | (w11 >> 19)) ^ ((w11 << 3) | (w11 >> 61)) ^ (w11 >> 6)) + w6 + (((w14 << 63) | (w14 >> 1)) ^ ((w14 << 56) | (w14 >> 8)) ^ (w14 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0xa4506cebde82bde9ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w14 += (((w12 << 45) | (w12 >> 19)) ^ ((w12 << 3) | (w12 >> 61)) ^ (w12 >> 6)) + w7 + (((w15 << 63) | (w15 >> 1)) ^ ((w15 << 56) | (w15 >> 8)) ^ (w15 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0xbef9a3f7b2c67915ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w15 += (((w13 << 45) | (w13 >> 19)) ^ ((w13 << 3) | (w13 >> 61)) ^ (w13 >> 6)) + w8 + (((w0 << 63) | (w0 >> 1)) ^ ((w0 << 56) | (w0 >> 8)) ^ (w0 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0xc67178f2e372532bULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	w0 += (((w14 << 45) | (w14 >> 19)) ^ ((w14 << 3) | (w14 >> 61)) ^ (w14 >> 6)) + w9 + (((w1 << 63) | (w1 >> 1)) ^ ((w1 << 56) | (w1 >> 8)) ^ (w1 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0xca273eceea26619cULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w1 += (((w15 << 45) | (w15 >> 19)) ^ ((w15 << 3) | (w15 >> 61)) ^ (w15 >> 6)) + w10 + (((w2 << 63) | (w2 >> 1)) ^ ((w2 << 56) | (w2 >> 8)) ^ (w2 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0xd186b8c721c0c207ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w2 += (((w0 << 45) | (w0 >> 19)) ^ ((w0 << 3) | (w0 >> 61)) ^ (w0 >> 6)) + w11 + (((w3 << 63) | (w3 >> 1)) ^ ((w3 << 56) | (w3 >> 8)) ^ (w3 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0xeada7dd6cde0eb1eULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w3 += (((w1 << 45) | (w1 >> 19)) ^ ((w1 << 3) | (w1 >> 61)) ^ (w1 >> 6)) + w12 + (((w4 << 63) | (w4 >> 1)) ^ ((w4 << 56) | (w4 >> 8)) ^ (w4 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0xf57d4f7fee6ed178ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w4 += (((w2 << 45) | (w2 >> 19)) ^ ((w2 << 3) | (w2 >> 61)) ^ (w2 >> 6)) + w13 + (((w5 << 63) | (w5 >> 1)) ^ ((w5 << 56) | (w5 >> 8)) ^ (w5 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x06f067aa72176fbaULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w5 += (((w3 << 45) | (w3 >> 19)) ^ ((w3 << 3) | (w3 >> 61)) ^ (w3 >> 6)) + w14 + (((w6 << 63) | (w6 >> 1)) ^ ((w6 << 56) | (w6 >> 8)) ^ (w6 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x0a637dc5a2c898a6ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w6 += (((w4 << 45) | (w4 >> 19)) ^ ((w4 << 3) | (w4 >> 61)) ^ (w4 >> 6)) + w15 + (((w7 << 63) | (w7 >> 1)) ^ ((w7 << 56) | (w7 >> 8)) ^ (w7 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x113f9804bef90daeULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w7 += (((w5 << 45) | (w5 >> 19)) ^ ((w5 << 3) | (w5 >> 61)) ^ (w5 >> 6)) + w0 + (((w8 << 63) | (w8 >> 1)) ^ ((w8 << 56) | (w8 >> 8)) ^ (w8 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0x1b710b35131c471bULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	w8 += (((w6 << 45) | (w6 >> 19)) ^ ((w6 << 3) | (w6 >> 61)) ^ (w6 >> 6)) + w1 + (((w9 << 63) | (w9 >> 1)) ^ ((w9 << 56) | (w9 >> 8)) ^ (w9 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0x28db77f523047d84ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w9 += (((w7 << 45) | (w7 >> 19)) ^ ((w7 << 3) | (w7 >> 61)) ^ (w7 >> 6)) + w2 + (((w10 << 63) | (w10 >> 1)) ^ ((w10 << 56) | (w10 >> 8)) ^ (w10 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0x32caab7b40c72493ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w10 += (((w8 << 45) | (w8 >> 19)) ^ ((w8 << 3) | (w8 >> 61)) ^ (w8 >> 6)) + w3 + (((w11 << 63) | (w11 >> 1)) ^ ((w11 << 56) | (w11 >> 8)) ^ (w11 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0x3c9ebe0a15c9bebcULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w11 += (((w9 << 45) | (w9 >> 19)) ^ ((w9 << 3) | (w9 >> 61)) ^ (w9 >> 6)) + w4 + (((w12 << 63) | (w12 >> 1)) ^ ((w12 << 56) | (w12 >> 8)) ^ (w12 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0x431d67c49c100d4cULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w12 += (((w10 << 45) | (w10 >> 19)) ^ ((w10 << 3) | (w10 >> 61)) ^ (w10 >> 6)) + w5 + (((w13 << 63) | (w13 >> 1)) ^ ((w13 << 56) | (w13 >> 8)) ^ (w13 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0x4cc5d4becb3e42b6ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w13 += (((w11 << 45) | (w11 >> 19)) ^ ((w11 << 3) | (w11 >> 61)) ^ (w11 >> 6)) + w6 + (((w14 << 63) | (w14 >> 1)) ^ ((w14 << 56) | (w14 >> 8)) ^ (w14 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0x597f299cfc657e2aULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w14 += (((w12 << 45) | (w12 >> 19)) ^ ((w12 << 3) | (w12 >> 61)) ^ (w12 >> 6)) + w7 + (((w15 << 63) | (w15 >> 1)) ^ ((w15 << 56) | (w15 >> 8)) ^ (w15 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0x5fcb6fab3ad6faecULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w15 += (((w13 << 45) | (w13 >> 19)) ^ ((w13 << 3) | (w13 >> 61)) ^ (w13 >> 6)) + w8 + (((w0 << 63) | (w0 >> 1)) ^ ((w0 << 56) | (w0 >> 8)) ^ (w0 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0x6c44198c4a475817ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	output[0] += a;
	output[1] += b;
	output[2] += c;
	output[3] += d;
	output[4] += e;
	output[5] += f;
	output[6] += g;
	output[7] += h;
}

/* SHA2-512 */

static const uint64_t sha512_iv[8] =
{
	0x6A09E667F3BCC908ULL,
	0xBB67AE8584CAA73BULL,
	0x3C6EF372FE94F82BULL,
	0xA54FF53A5F1D36F1ULL,
	0x510E527FADE682D1ULL,
	0x9B05688C2B3E6C1FULL,
	0x1F83D9ABFB41BD6BULL,
	0x5BE0CD19137E2179ULL
};

static void sha512_increase(sha512_state* state, size_t length)
{
	state->t[0] += length;

	if (state->t[0] > 0x1FFFFFFFFFFFFFFFULL)
	{
		state->t[1] += (uint64_t)(state->t[0] >> 61);
		state->t[0] &= 0x1FFFFFFFFFFFFFFFULL;
	}
}

void sha2_compute512(uint8_t* output, const uint8_t* message, size_t msglen)
{
	sha512_state state;
	size_t blocks;

	sha512_initialize(&state);
	blocks = msglen / SHA2_512_RATE;

	if (msglen >= SHA2_512_RATE)
	{
		sha512_blockupdate(&state, message, blocks);
		msglen -= blocks * SHA2_512_RATE;
	}

	sha512_finalize(&state, output, message + (blocks * SHA2_512_RATE), msglen);
}

void sha512_blockupdate(sha512_state* state, const uint8_t* message, size_t nblocks)
{
	size_t i;

	for (i = 0; i < nblocks; ++i)
	{
		sha512_permute(state->state, message + (i * SHA2_512_RATE));
		sha512_increase(state, SHA2_512_RATE);
	}
}

void sha512_finalize(sha512_state* state, uint8_t* output, const uint8_t* message, size_t msglen)
{
	uint8_t pad[SHA2_512_RATE] = { 0 };
	uint64_t bitLen;
	size_t i;

	sha512_increase(state, msglen);
	bitLen = (state->t[0] << 3);

	for (i = 0; i < msglen; ++i)
	{
		pad[i] = message[i];
	}

	if (msglen == SHA2_512_RATE)
	{
		sha512_permute(state->state, pad);
		msglen = 0;
	}

	pad[msglen] = 128;
	++msglen;

	/* padding */
	if (msglen < SHA2_512_RATE)
	{
		clear8(pad + msglen, SHA2_512_RATE - msglen);
	}

	if (msglen > 112)
	{
		sha512_permute(state->state, pad);
		clear8(pad, SHA2_512_RATE);
	}

	/* finalize state with counter and last compression */
	be64to8(pad + 112, state->t[1]);
	be64to8(pad + 120, bitLen);
	sha512_permute(state->state, pad);

	for (i = 0; i < SHA2_512_HASH; i += 8)
	{
		be64to8(output + i, state->state[i / 8]);
	}
}

void sha512_initialize(sha512_state* state)
{
	size_t i;

	for (i = 0; i < SHA2_STATE_SIZE; ++i)
	{
		state->state[i] = sha512_iv[i];
	}

	state->t[0] = 0;
	state->t[1] = 0;
}

void sha512_permute(uint64_t* output, const uint8_t* message)
{
	uint64_t a;
	uint64_t b;
	uint64_t c;
	uint64_t d;
	uint64_t e;
	uint64_t f;
	uint64_t g;
	uint64_t h;
	uint64_t r;
	uint64_t w0;
	uint64_t w1;
	uint64_t w2;
	uint64_t w3;
	uint64_t w4;
	uint64_t w5;
	uint64_t w6;
	uint64_t w7;
	uint64_t w8;
	uint64_t w9;
	uint64_t w10;
	uint64_t w11;
	uint64_t w12;
	uint64_t w13;
	uint64_t w14;
	uint64_t w15;

	a = output[0];
	b = output[1];
	c = output[2];
	d = output[3];
	e = output[4];
	f = output[5];
	g = output[6];
	h = output[7];

	w0 = be8to64(message);
	w1 = be8to64(message + 8);
	w2 = be8to64(message + 16);
	w3 = be8to64(message + 24);
	w4 = be8to64(message + 32);
	w5 = be8to64(message + 40);
	w6 = be8to64(message + 48);
	w7 = be8to64(message + 56);
	w8 = be8to64(message + 64);
	w9 = be8to64(message + 72);
	w10 = be8to64(message + 80);
	w11 = be8to64(message + 88);
	w12 = be8to64(message + 96);
	w13 = be8to64(message + 104);
	w14 = be8to64(message + 112);
	w15 = be8to64(message + 120);

	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0x428a2f98d728ae22ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0x7137449123ef65cdULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0xb5c0fbcfec4d3b2fULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0xe9b5dba58189dbbcULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x3956c25bf348b538ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x59f111f1b605d019ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x923f82a4af194f9bULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0xab1c5ed5da6d8118ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0xd807aa98a3030242ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0x12835b0145706fbeULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0x243185be4ee4b28cULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0x550c7dc3d5ffb4e2ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0x72be5d74f27b896fULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0x80deb1fe3b1696b1ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0x9bdc06a725c71235ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0xc19bf174cf692694ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	w0 += (((w14 << 45) | (w14 >> 19)) ^ ((w14 << 3) | (w14 >> 61)) ^ (w14 >> 6)) + w9 + (((w1 << 63) | (w1 >> 1)) ^ ((w1 << 56) | (w1 >> 8)) ^ (w1 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0xe49b69c19ef14ad2ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w1 += (((w15 << 45) | (w15 >> 19)) ^ ((w15 << 3) | (w15 >> 61)) ^ (w15 >> 6)) + w10 + (((w2 << 63) | (w2 >> 1)) ^ ((w2 << 56) | (w2 >> 8)) ^ (w2 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0xefbe4786384f25e3ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w2 += (((w0 << 45) | (w0 >> 19)) ^ ((w0 << 3) | (w0 >> 61)) ^ (w0 >> 6)) + w11 + (((w3 << 63) | (w3 >> 1)) ^ ((w3 << 56) | (w3 >> 8)) ^ (w3 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0x0fc19dc68b8cd5b5ULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w3 += (((w1 << 45) | (w1 >> 19)) ^ ((w1 << 3) | (w1 >> 61)) ^ (w1 >> 6)) + w12 + (((w4 << 63) | (w4 >> 1)) ^ ((w4 << 56) | (w4 >> 8)) ^ (w4 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0x240ca1cc77ac9c65ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w4 += (((w2 << 45) | (w2 >> 19)) ^ ((w2 << 3) | (w2 >> 61)) ^ (w2 >> 6)) + w13 + (((w5 << 63) | (w5 >> 1)) ^ ((w5 << 56) | (w5 >> 8)) ^ (w5 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x2de92c6f592b0275ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w5 += (((w3 << 45) | (w3 >> 19)) ^ ((w3 << 3) | (w3 >> 61)) ^ (w3 >> 6)) + w14 + (((w6 << 63) | (w6 >> 1)) ^ ((w6 << 56) | (w6 >> 8)) ^ (w6 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x4a7484aa6ea6e483ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w6 += (((w4 << 45) | (w4 >> 19)) ^ ((w4 << 3) | (w4 >> 61)) ^ (w4 >> 6)) + w15 + (((w7 << 63) | (w7 >> 1)) ^ ((w7 << 56) | (w7 >> 8)) ^ (w7 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x5cb0a9dcbd41fbd4ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w7 += (((w5 << 45) | (w5 >> 19)) ^ ((w5 << 3) | (w5 >> 61)) ^ (w5 >> 6)) + w0 + (((w8 << 63) | (w8 >> 1)) ^ ((w8 << 56) | (w8 >> 8)) ^ (w8 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0x76f988da831153b5ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	w8 += (((w6 << 45) | (w6 >> 19)) ^ ((w6 << 3) | (w6 >> 61)) ^ (w6 >> 6)) + w1 + (((w9 << 63) | (w9 >> 1)) ^ ((w9 << 56) | (w9 >> 8)) ^ (w9 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0x983e5152ee66dfabULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w9 += (((w7 << 45) | (w7 >> 19)) ^ ((w7 << 3) | (w7 >> 61)) ^ (w7 >> 6)) + w2 + (((w10 << 63) | (w10 >> 1)) ^ ((w10 << 56) | (w10 >> 8)) ^ (w10 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0xa831c66d2db43210ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w10 += (((w8 << 45) | (w8 >> 19)) ^ ((w8 << 3) | (w8 >> 61)) ^ (w8 >> 6)) + w3 + (((w11 << 63) | (w11 >> 1)) ^ ((w11 << 56) | (w11 >> 8)) ^ (w11 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0xb00327c898fb213fULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w11 += (((w9 << 45) | (w9 >> 19)) ^ ((w9 << 3) | (w9 >> 61)) ^ (w9 >> 6)) + w4 + (((w12 << 63) | (w12 >> 1)) ^ ((w12 << 56) | (w12 >> 8)) ^ (w12 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0xbf597fc7beef0ee4ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w12 += (((w10 << 45) | (w10 >> 19)) ^ ((w10 << 3) | (w10 >> 61)) ^ (w10 >> 6)) + w5 + (((w13 << 63) | (w13 >> 1)) ^ ((w13 << 56) | (w13 >> 8)) ^ (w13 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0xc6e00bf33da88fc2ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w13 += (((w11 << 45) | (w11 >> 19)) ^ ((w11 << 3) | (w11 >> 61)) ^ (w11 >> 6)) + w6 + (((w14 << 63) | (w14 >> 1)) ^ ((w14 << 56) | (w14 >> 8)) ^ (w14 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0xd5a79147930aa725ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w14 += (((w12 << 45) | (w12 >> 19)) ^ ((w12 << 3) | (w12 >> 61)) ^ (w12 >> 6)) + w7 + (((w15 << 63) | (w15 >> 1)) ^ ((w15 << 56) | (w15 >> 8)) ^ (w15 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0x06ca6351e003826fULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w15 += (((w13 << 45) | (w13 >> 19)) ^ ((w13 << 3) | (w13 >> 61)) ^ (w13 >> 6)) + w8 + (((w0 << 63) | (w0 >> 1)) ^ ((w0 << 56) | (w0 >> 8)) ^ (w0 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0x142929670a0e6e70ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	w0 += (((w14 << 45) | (w14 >> 19)) ^ ((w14 << 3) | (w14 >> 61)) ^ (w14 >> 6)) + w9 + (((w1 << 63) | (w1 >> 1)) ^ ((w1 << 56) | (w1 >> 8)) ^ (w1 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0x27b70a8546d22ffcULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w1 += (((w15 << 45) | (w15 >> 19)) ^ ((w15 << 3) | (w15 >> 61)) ^ (w15 >> 6)) + w10 + (((w2 << 63) | (w2 >> 1)) ^ ((w2 << 56) | (w2 >> 8)) ^ (w2 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0x2e1b21385c26c926ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w2 += (((w0 << 45) | (w0 >> 19)) ^ ((w0 << 3) | (w0 >> 61)) ^ (w0 >> 6)) + w11 + (((w3 << 63) | (w3 >> 1)) ^ ((w3 << 56) | (w3 >> 8)) ^ (w3 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0x4d2c6dfc5ac42aedULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w3 += (((w1 << 45) | (w1 >> 19)) ^ ((w1 << 3) | (w1 >> 61)) ^ (w1 >> 6)) + w12 + (((w4 << 63) | (w4 >> 1)) ^ ((w4 << 56) | (w4 >> 8)) ^ (w4 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0x53380d139d95b3dfULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w4 += (((w2 << 45) | (w2 >> 19)) ^ ((w2 << 3) | (w2 >> 61)) ^ (w2 >> 6)) + w13 + (((w5 << 63) | (w5 >> 1)) ^ ((w5 << 56) | (w5 >> 8)) ^ (w5 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x650a73548baf63deULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w5 += (((w3 << 45) | (w3 >> 19)) ^ ((w3 << 3) | (w3 >> 61)) ^ (w3 >> 6)) + w14 + (((w6 << 63) | (w6 >> 1)) ^ ((w6 << 56) | (w6 >> 8)) ^ (w6 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x766a0abb3c77b2a8ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w6 += (((w4 << 45) | (w4 >> 19)) ^ ((w4 << 3) | (w4 >> 61)) ^ (w4 >> 6)) + w15 + (((w7 << 63) | (w7 >> 1)) ^ ((w7 << 56) | (w7 >> 8)) ^ (w7 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x81c2c92e47edaee6ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w7 += (((w5 << 45) | (w5 >> 19)) ^ ((w5 << 3) | (w5 >> 61)) ^ (w5 >> 6)) + w0 + (((w8 << 63) | (w8 >> 1)) ^ ((w8 << 56) | (w8 >> 8)) ^ (w8 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0x92722c851482353bULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	w8 += (((w6 << 45) | (w6 >> 19)) ^ ((w6 << 3) | (w6 >> 61)) ^ (w6 >> 6)) + w1 + (((w9 << 63) | (w9 >> 1)) ^ ((w9 << 56) | (w9 >> 8)) ^ (w9 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0xa2bfe8a14cf10364ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w9 += (((w7 << 45) | (w7 >> 19)) ^ ((w7 << 3) | (w7 >> 61)) ^ (w7 >> 6)) + w2 + (((w10 << 63) | (w10 >> 1)) ^ ((w10 << 56) | (w10 >> 8)) ^ (w10 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0xa81a664bbc423001ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w10 += (((w8 << 45) | (w8 >> 19)) ^ ((w8 << 3) | (w8 >> 61)) ^ (w8 >> 6)) + w3 + (((w11 << 63) | (w11 >> 1)) ^ ((w11 << 56) | (w11 >> 8)) ^ (w11 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0xc24b8b70d0f89791ULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w11 += (((w9 << 45) | (w9 >> 19)) ^ ((w9 << 3) | (w9 >> 61)) ^ (w9 >> 6)) + w4 + (((w12 << 63) | (w12 >> 1)) ^ ((w12 << 56) | (w12 >> 8)) ^ (w12 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0xc76c51a30654be30ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w12 += (((w10 << 45) | (w10 >> 19)) ^ ((w10 << 3) | (w10 >> 61)) ^ (w10 >> 6)) + w5 + (((w13 << 63) | (w13 >> 1)) ^ ((w13 << 56) | (w13 >> 8)) ^ (w13 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0xd192e819d6ef5218ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w13 += (((w11 << 45) | (w11 >> 19)) ^ ((w11 << 3) | (w11 >> 61)) ^ (w11 >> 6)) + w6 + (((w14 << 63) | (w14 >> 1)) ^ ((w14 << 56) | (w14 >> 8)) ^ (w14 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0xd69906245565a910ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w14 += (((w12 << 45) | (w12 >> 19)) ^ ((w12 << 3) | (w12 >> 61)) ^ (w12 >> 6)) + w7 + (((w15 << 63) | (w15 >> 1)) ^ ((w15 << 56) | (w15 >> 8)) ^ (w15 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0xf40e35855771202aULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w15 += (((w13 << 45) | (w13 >> 19)) ^ ((w13 << 3) | (w13 >> 61)) ^ (w13 >> 6)) + w8 + (((w0 << 63) | (w0 >> 1)) ^ ((w0 << 56) | (w0 >> 8)) ^ (w0 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0x106aa07032bbd1b8ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	w0 += (((w14 << 45) | (w14 >> 19)) ^ ((w14 << 3) | (w14 >> 61)) ^ (w14 >> 6)) + w9 + (((w1 << 63) | (w1 >> 1)) ^ ((w1 << 56) | (w1 >> 8)) ^ (w1 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0x19a4c116b8d2d0c8ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w1 += (((w15 << 45) | (w15 >> 19)) ^ ((w15 << 3) | (w15 >> 61)) ^ (w15 >> 6)) + w10 + (((w2 << 63) | (w2 >> 1)) ^ ((w2 << 56) | (w2 >> 8)) ^ (w2 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0x1e376c085141ab53ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w2 += (((w0 << 45) | (w0 >> 19)) ^ ((w0 << 3) | (w0 >> 61)) ^ (w0 >> 6)) + w11 + (((w3 << 63) | (w3 >> 1)) ^ ((w3 << 56) | (w3 >> 8)) ^ (w3 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0x2748774cdf8eeb99ULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w3 += (((w1 << 45) | (w1 >> 19)) ^ ((w1 << 3) | (w1 >> 61)) ^ (w1 >> 6)) + w12 + (((w4 << 63) | (w4 >> 1)) ^ ((w4 << 56) | (w4 >> 8)) ^ (w4 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0x34b0bcb5e19b48a8ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w4 += (((w2 << 45) | (w2 >> 19)) ^ ((w2 << 3) | (w2 >> 61)) ^ (w2 >> 6)) + w13 + (((w5 << 63) | (w5 >> 1)) ^ ((w5 << 56) | (w5 >> 8)) ^ (w5 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x391c0cb3c5c95a63ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w5 += (((w3 << 45) | (w3 >> 19)) ^ ((w3 << 3) | (w3 >> 61)) ^ (w3 >> 6)) + w14 + (((w6 << 63) | (w6 >> 1)) ^ ((w6 << 56) | (w6 >> 8)) ^ (w6 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x4ed8aa4ae3418acbULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w6 += (((w4 << 45) | (w4 >> 19)) ^ ((w4 << 3) | (w4 >> 61)) ^ (w4 >> 6)) + w15 + (((w7 << 63) | (w7 >> 1)) ^ ((w7 << 56) | (w7 >> 8)) ^ (w7 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x5b9cca4f7763e373ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w7 += (((w5 << 45) | (w5 >> 19)) ^ ((w5 << 3) | (w5 >> 61)) ^ (w5 >> 6)) + w0 + (((w8 << 63) | (w8 >> 1)) ^ ((w8 << 56) | (w8 >> 8)) ^ (w8 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0x682e6ff3d6b2b8a3ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	w8 += (((w6 << 45) | (w6 >> 19)) ^ ((w6 << 3) | (w6 >> 61)) ^ (w6 >> 6)) + w1 + (((w9 << 63) | (w9 >> 1)) ^ ((w9 << 56) | (w9 >> 8)) ^ (w9 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0x748f82ee5defb2fcULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w9 += (((w7 << 45) | (w7 >> 19)) ^ ((w7 << 3) | (w7 >> 61)) ^ (w7 >> 6)) + w2 + (((w10 << 63) | (w10 >> 1)) ^ ((w10 << 56) | (w10 >> 8)) ^ (w10 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0x78a5636f43172f60ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w10 += (((w8 << 45) | (w8 >> 19)) ^ ((w8 << 3) | (w8 >> 61)) ^ (w8 >> 6)) + w3 + (((w11 << 63) | (w11 >> 1)) ^ ((w11 << 56) | (w11 >> 8)) ^ (w11 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0x84c87814a1f0ab72ULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w11 += (((w9 << 45) | (w9 >> 19)) ^ ((w9 << 3) | (w9 >> 61)) ^ (w9 >> 6)) + w4 + (((w12 << 63) | (w12 >> 1)) ^ ((w12 << 56) | (w12 >> 8)) ^ (w12 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0x8cc702081a6439ecULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w12 += (((w10 << 45) | (w10 >> 19)) ^ ((w10 << 3) | (w10 >> 61)) ^ (w10 >> 6)) + w5 + (((w13 << 63) | (w13 >> 1)) ^ ((w13 << 56) | (w13 >> 8)) ^ (w13 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0x90befffa23631e28ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w13 += (((w11 << 45) | (w11 >> 19)) ^ ((w11 << 3) | (w11 >> 61)) ^ (w11 >> 6)) + w6 + (((w14 << 63) | (w14 >> 1)) ^ ((w14 << 56) | (w14 >> 8)) ^ (w14 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0xa4506cebde82bde9ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w14 += (((w12 << 45) | (w12 >> 19)) ^ ((w12 << 3) | (w12 >> 61)) ^ (w12 >> 6)) + w7 + (((w15 << 63) | (w15 >> 1)) ^ ((w15 << 56) | (w15 >> 8)) ^ (w15 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0xbef9a3f7b2c67915ULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w15 += (((w13 << 45) | (w13 >> 19)) ^ ((w13 << 3) | (w13 >> 61)) ^ (w13 >> 6)) + w8 + (((w0 << 63) | (w0 >> 1)) ^ ((w0 << 56) | (w0 >> 8)) ^ (w0 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0xc67178f2e372532bULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	w0 += (((w14 << 45) | (w14 >> 19)) ^ ((w14 << 3) | (w14 >> 61)) ^ (w14 >> 6)) + w9 + (((w1 << 63) | (w1 >> 1)) ^ ((w1 << 56) | (w1 >> 8)) ^ (w1 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w0 + 0xca273eceea26619cULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w1 += (((w15 << 45) | (w15 >> 19)) ^ ((w15 << 3) | (w15 >> 61)) ^ (w15 >> 6)) + w10 + (((w2 << 63) | (w2 >> 1)) ^ ((w2 << 56) | (w2 >> 8)) ^ (w2 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w1 + 0xd186b8c721c0c207ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w2 += (((w0 << 45) | (w0 >> 19)) ^ ((w0 << 3) | (w0 >> 61)) ^ (w0 >> 6)) + w11 + (((w3 << 63) | (w3 >> 1)) ^ ((w3 << 56) | (w3 >> 8)) ^ (w3 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w2 + 0xeada7dd6cde0eb1eULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w3 += (((w1 << 45) | (w1 >> 19)) ^ ((w1 << 3) | (w1 >> 61)) ^ (w1 >> 6)) + w12 + (((w4 << 63) | (w4 >> 1)) ^ ((w4 << 56) | (w4 >> 8)) ^ (w4 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w3 + 0xf57d4f7fee6ed178ULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w4 += (((w2 << 45) | (w2 >> 19)) ^ ((w2 << 3) | (w2 >> 61)) ^ (w2 >> 6)) + w13 + (((w5 << 63) | (w5 >> 1)) ^ ((w5 << 56) | (w5 >> 8)) ^ (w5 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w4 + 0x06f067aa72176fbaULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w5 += (((w3 << 45) | (w3 >> 19)) ^ ((w3 << 3) | (w3 >> 61)) ^ (w3 >> 6)) + w14 + (((w6 << 63) | (w6 >> 1)) ^ ((w6 << 56) | (w6 >> 8)) ^ (w6 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w5 + 0x0a637dc5a2c898a6ULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w6 += (((w4 << 45) | (w4 >> 19)) ^ ((w4 << 3) | (w4 >> 61)) ^ (w4 >> 6)) + w15 + (((w7 << 63) | (w7 >> 1)) ^ ((w7 << 56) | (w7 >> 8)) ^ (w7 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w6 + 0x113f9804bef90daeULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w7 += (((w5 << 45) | (w5 >> 19)) ^ ((w5 << 3) | (w5 >> 61)) ^ (w5 >> 6)) + w0 + (((w8 << 63) | (w8 >> 1)) ^ ((w8 << 56) | (w8 >> 8)) ^ (w8 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w7 + 0x1b710b35131c471bULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));
	w8 += (((w6 << 45) | (w6 >> 19)) ^ ((w6 << 3) | (w6 >> 61)) ^ (w6 >> 6)) + w1 + (((w9 << 63) | (w9 >> 1)) ^ ((w9 << 56) | (w9 >> 8)) ^ (w9 >> 7));
	r = h + (((e << 50) | (e >> 14)) ^ ((e << 46) | (e >> 18)) ^ ((e << 23) | (e >> 41))) + ((e & f) ^ (~e & g)) + w8 + 0x28db77f523047d84ULL;
	d += r;
	h = r + (((a << 36) | (a >> 28)) ^ ((a << 30) | (a >> 34)) ^ ((a << 25) | (a >> 39))) + ((a & b) ^ (a & c) ^ (b & c));
	w9 += (((w7 << 45) | (w7 >> 19)) ^ ((w7 << 3) | (w7 >> 61)) ^ (w7 >> 6)) + w2 + (((w10 << 63) | (w10 >> 1)) ^ ((w10 << 56) | (w10 >> 8)) ^ (w10 >> 7));
	r = g + (((d << 50) | (d >> 14)) ^ ((d << 46) | (d >> 18)) ^ ((d << 23) | (d >> 41))) + ((d & e) ^ (~d & f)) + w9 + 0x32caab7b40c72493ULL;
	c += r;
	g = r + (((h << 36) | (h >> 28)) ^ ((h << 30) | (h >> 34)) ^ ((h << 25) | (h >> 39))) + ((h & a) ^ (h & b) ^ (a & b));
	w10 += (((w8 << 45) | (w8 >> 19)) ^ ((w8 << 3) | (w8 >> 61)) ^ (w8 >> 6)) + w3 + (((w11 << 63) | (w11 >> 1)) ^ ((w11 << 56) | (w11 >> 8)) ^ (w11 >> 7));
	r = f + (((c << 50) | (c >> 14)) ^ ((c << 46) | (c >> 18)) ^ ((c << 23) | (c >> 41))) + ((c & d) ^ (~c & e)) + w10 + 0x3c9ebe0a15c9bebcULL;
	b += r;
	f = r + (((g << 36) | (g >> 28)) ^ ((g << 30) | (g >> 34)) ^ ((g << 25) | (g >> 39))) + ((g & h) ^ (g & a) ^ (h & a));
	w11 += (((w9 << 45) | (w9 >> 19)) ^ ((w9 << 3) | (w9 >> 61)) ^ (w9 >> 6)) + w4 + (((w12 << 63) | (w12 >> 1)) ^ ((w12 << 56) | (w12 >> 8)) ^ (w12 >> 7));
	r = e + (((b << 50) | (b >> 14)) ^ ((b << 46) | (b >> 18)) ^ ((b << 23) | (b >> 41))) + ((b & c) ^ (~b & d)) + w11 + 0x431d67c49c100d4cULL;
	a += r;
	e = r + (((f << 36) | (f >> 28)) ^ ((f << 30) | (f >> 34)) ^ ((f << 25) | (f >> 39))) + ((f & g) ^ (f & h) ^ (g & h));
	w12 += (((w10 << 45) | (w10 >> 19)) ^ ((w10 << 3) | (w10 >> 61)) ^ (w10 >> 6)) + w5 + (((w13 << 63) | (w13 >> 1)) ^ ((w13 << 56) | (w13 >> 8)) ^ (w13 >> 7));
	r = d + (((a << 50) | (a >> 14)) ^ ((a << 46) | (a >> 18)) ^ ((a << 23) | (a >> 41))) + ((a & b) ^ (~a & c)) + w12 + 0x4cc5d4becb3e42b6ULL;
	h += r;
	d = r + (((e << 36) | (e >> 28)) ^ ((e << 30) | (e >> 34)) ^ ((e << 25) | (e >> 39))) + ((e & f) ^ (e & g) ^ (f & g));
	w13 += (((w11 << 45) | (w11 >> 19)) ^ ((w11 << 3) | (w11 >> 61)) ^ (w11 >> 6)) + w6 + (((w14 << 63) | (w14 >> 1)) ^ ((w14 << 56) | (w14 >> 8)) ^ (w14 >> 7));
	r = c + (((h << 50) | (h >> 14)) ^ ((h << 46) | (h >> 18)) ^ ((h << 23) | (h >> 41))) + ((h & a) ^ (~h & b)) + w13 + 0x597f299cfc657e2aULL;
	g += r;
	c = r + (((d << 36) | (d >> 28)) ^ ((d << 30) | (d >> 34)) ^ ((d << 25) | (d >> 39))) + ((d & e) ^ (d & f) ^ (e & f));
	w14 += (((w12 << 45) | (w12 >> 19)) ^ ((w12 << 3) | (w12 >> 61)) ^ (w12 >> 6)) + w7 + (((w15 << 63) | (w15 >> 1)) ^ ((w15 << 56) | (w15 >> 8)) ^ (w15 >> 7));
	r = b + (((g << 50) | (g >> 14)) ^ ((g << 46) | (g >> 18)) ^ ((g << 23) | (g >> 41))) + ((g & h) ^ (~g & a)) + w14 + 0x5fcb6fab3ad6faecULL;
	f += r;
	b = r + (((c << 36) | (c >> 28)) ^ ((c << 30) | (c >> 34)) ^ ((c << 25) | (c >> 39))) + ((c & d) ^ (c & e) ^ (d & e));
	w15 += (((w13 << 45) | (w13 >> 19)) ^ ((w13 << 3) | (w13 >> 61)) ^ (w13 >> 6)) + w8 + (((w0 << 63) | (w0 >> 1)) ^ ((w0 << 56) | (w0 >> 8)) ^ (w0 >> 7));
	r = a + (((f << 50) | (f >> 14)) ^ ((f << 46) | (f >> 18)) ^ ((f << 23) | (f >> 41))) + ((f & g) ^ (~f & h)) + w15 + 0x6c44198c4a475817ULL;
	e += r;
	a = r + (((b << 36) | (b >> 28)) ^ ((b << 30) | (b >> 34)) ^ ((b << 25) | (b >> 39))) + ((b & c) ^ (b & d) ^ (c & d));

	output[0] += a;
	output[1] += b;
	output[2] += c;
	output[3] += d;
	output[4] += e;
	output[5] += f;
	output[6] += g;
	output[7] += h;
}

/* HMAC-256 */

void hmac256_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen)
{
	const uint8_t IPAD = 0x36;
	const uint8_t OPAD = 0x5C;
	uint8_t ipad[SHA2_256_RATE] = { 0 };
	uint8_t opad[SHA2_256_RATE];
	uint8_t tmpv[SHA2_256_HASH];
	sha256_state state;
	size_t i;

	if (keylen > SHA2_256_RATE)
	{
		sha256_initialize(&state);

		while (keylen > SHA2_256_RATE)
		{
			sha256_blockupdate(&state, key, 1);
			keylen -= SHA2_256_RATE;
		}

		sha256_finalize(&state, ipad, key, keylen);
	}
	else
	{
		for (i = 0; i < keylen; ++i)
		{
			ipad[i] = key[i];
		}
	}

	for (i = 0; i < SHA2_256_RATE; ++i)
	{
		opad[i] = ipad[i];
		opad[i] ^= OPAD;
		ipad[i] ^= IPAD;
	}

	sha256_initialize(&state);
	sha256_blockupdate(&state, ipad, 1);

	while (msglen >= SHA2_256_RATE)
	{
		sha256_blockupdate(&state, message, 1);
		msglen -= SHA2_256_RATE;
		message += SHA2_256_RATE;
	}

	sha256_finalize(&state, tmpv, message, msglen);
	sha256_initialize(&state);
	sha256_blockupdate(&state, opad, 1);
	sha256_finalize(&state, output, tmpv, SHA2_256_HASH);
}

void hmac256_blockupdate(hmac256_state* state, const uint8_t* message, size_t nblocks)
{
	sha256_blockupdate(&state->pstate, message, nblocks);
}

void hmac256_finalize(hmac256_state* state, uint8_t* output, const uint8_t* message, size_t msglen)
{
	uint8_t tmpv[SHA2_256_HASH];
	size_t oft;

	oft = 0;

	while (msglen >= SHA2_256_RATE)
	{
		sha256_blockupdate(&state->pstate, message + oft, 1);
		oft += SHA2_256_RATE;
		msglen -= SHA2_256_RATE;
	}

	sha256_finalize(&state->pstate, tmpv, message + oft, msglen);
	sha256_initialize(&state->pstate);
	sha256_blockupdate(&state->pstate, state->opad, 1);
	sha256_finalize(&state->pstate, output, tmpv, SHA2_256_HASH);
}

void hmac256_initialize(hmac256_state* state, const uint8_t* key, size_t keylen)
{
	const uint8_t IPAD = 0x36;
	const uint8_t OPAD = 0x5C;
	size_t i;
	size_t oft;

	oft = 0;
	clear8(state->ipad, SHA2_256_RATE);

	if (keylen > SHA2_256_RATE)
	{
		sha256_initialize(&state->pstate);

		while (keylen > SHA2_256_RATE)
		{
			sha256_blockupdate(&state->pstate, key + oft, 1);
			oft += SHA2_256_RATE;
			keylen -= SHA2_256_RATE;
		}

		sha256_finalize(&state->pstate, state->ipad, key + oft, keylen);
	}
	else
	{
		for (i = 0; i < keylen; ++i)
		{
			state->ipad[i] = key[i];
		}
	}

	for (i = 0; i < SHA2_256_RATE; ++i)
	{
		state->opad[i] = state->ipad[i];
		state->opad[i] ^= OPAD;
		state->ipad[i] ^= IPAD;
	}

	sha256_initialize(&state->pstate);
	sha256_blockupdate(&state->pstate, state->ipad, 1);
}

/* HMAC-512 */

void hmac512_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen)
{
	const uint8_t IPAD = 0x36;
	const uint8_t OPAD = 0x5C;
	uint8_t ipad[SHA2_512_RATE] = { 0 };
	uint8_t opad[SHA2_512_RATE];
	uint8_t tmpv[SHA2_512_HASH];
	sha512_state state;
	size_t i;

	if (keylen > SHA2_512_RATE)
	{
		sha512_initialize(&state);

		while (keylen > SHA2_512_RATE)
		{
			sha512_blockupdate(&state, key, 1);
			keylen -= SHA2_512_RATE;
		}

		sha512_finalize(&state, ipad, key, keylen);
	}
	else
	{
		for (i = 0; i < keylen; ++i)
		{
			ipad[i] = key[i];
		}
	}

	for (i = 0; i < SHA2_512_RATE; ++i)
	{
		opad[i] = ipad[i];
		opad[i] ^= OPAD;
		ipad[i] ^= IPAD;
	}

	sha512_initialize(&state);
	sha512_blockupdate(&state, ipad, 1);

	while (msglen >= SHA2_512_RATE)
	{
		sha512_blockupdate(&state, message, 1);
		msglen -= SHA2_512_RATE;
		message += SHA2_512_RATE;
	}

	sha512_finalize(&state, tmpv, message, msglen);
	sha512_initialize(&state);
	sha512_blockupdate(&state, opad, 1);
	sha512_finalize(&state, output, tmpv, SHA2_512_HASH);
}

void hmac512_blockupdate(hmac512_state* state, const uint8_t* message, size_t nblocks)
{
	sha512_blockupdate(&state->pstate, message, nblocks);
}

void hmac512_finalize(hmac512_state* state, uint8_t* output, const uint8_t* message, size_t msglen)
{
	uint8_t tmpv[SHA2_512_HASH];
	size_t oft;

	oft = 0;

	while (msglen >= SHA2_512_RATE)
	{
		sha512_blockupdate(&state->pstate, message + oft, 1);
		oft += SHA2_512_RATE;
		msglen -= SHA2_512_RATE;
	}

	sha512_finalize(&state->pstate, tmpv, message + oft, msglen);
	sha512_initialize(&state->pstate);
	sha512_blockupdate(&state->pstate, state->opad, 1);
	sha512_finalize(&state->pstate, output, tmpv, SHA2_512_HASH);
}

void hmac512_initialize(hmac512_state* state, const uint8_t* key, size_t keylen)
{
	const uint8_t IPAD = 0x36;
	const uint8_t OPAD = 0x5C;
	size_t i;
	size_t oft;

	oft = 0;
	clear8(state->ipad, SHA2_512_RATE);

	if (keylen > SHA2_512_RATE)
	{
		sha512_initialize(&state->pstate);

		while (keylen > SHA2_512_RATE)
		{
			sha512_blockupdate(&state->pstate, key + oft, 1);
			keylen -= SHA2_512_RATE;
			oft += SHA2_512_RATE;
		}

		sha512_finalize(&state->pstate, state->ipad, key + oft, keylen);
	}
	else
	{
		for (i = 0; i < keylen; ++i)
		{
			state->ipad[i] = key[i];
		}
	}

	for (i = 0; i < SHA2_512_RATE; ++i)
	{
		state->opad[i] = state->ipad[i];
		state->opad[i] ^= OPAD;
		state->ipad[i] ^= IPAD;
	}

	sha512_initialize(&state->pstate);
	sha512_blockupdate(&state->pstate, state->ipad, 1);
}

/* HKDF-256 */

void hkdf256_expand(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen)
{
	hmac256_state state;
	uint8_t msg[SHA2_256_RATE] = { 0 };
	uint8_t otp[SHA2_256_HASH] = { 0 };
	size_t ctr;
	size_t i;
	size_t ioft;
	size_t mlen;
	size_t rmd;
	size_t slen;

	ctr = 0;
	slen = 0;

	while (outlen != 0)
	{
		hmac256_initialize(&state, key, keylen);
		mlen = infolen;
		ioft = 0;

		if (ctr != 0)
		{
			for (i = 0; i < SHA2_256_HASH; ++i)
			{
				msg[i] = otp[i];
			}

			slen = SHA2_256_HASH;

			if (infolen >= SHA2_256_HASH)
			{
				for (i = 0; i < SHA2_256_HASH; ++i)
				{
					msg[slen + i] = info[i];
				}

				hmac256_blockupdate(&state, msg, 1);
				mlen -= SHA2_256_HASH;
				ioft += SHA2_256_HASH;
				slen = 0;
			}

			while (mlen >= SHA2_256_RATE)
			{
				hmac256_blockupdate(&state, info + ioft, 1);
				ioft += SHA2_256_RATE;
				mlen -= SHA2_256_RATE;
			}

			for (i = 0; i < mlen; ++i)
			{
				msg[slen + i] = info[ioft + i];
			}

			++ctr;
			msg[slen + mlen] = (uint8_t)ctr;
			hmac256_finalize(&state, otp, msg, slen + mlen + 1);
		}
		else
		{
			while (mlen >= SHA2_256_RATE)
			{
				hmac256_blockupdate(&state, info + ioft, 1);
				ioft += SHA2_256_RATE;
				mlen -= SHA2_256_RATE;
			}

			for (i = 0; i < mlen; ++i)
			{
				msg[i] = info[ioft + i];
			}

			++ctr;
			msg[mlen] = (uint8_t)ctr;
			hmac256_finalize(&state, otp, msg, mlen + 1);
		}

		rmd = min((uint32_t)outlen, SHA2_256_HASH);

		for (i = 0; i < rmd; ++i)
		{
			output[i] = otp[i];
		}

		outlen -= rmd;
		output += rmd;
	}
}

void hkdf256_extract(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen)
{
	hmac256_state state;

	if (saltlen != 0)
	{
		hmac256_initialize(&state, salt, saltlen);
	}
	else
	{
		uint8_t tmp[HMAC_256_MAC] = { 0 };
		hmac256_initialize(&state, tmp, sizeof(tmp));
	}

	hmac256_finalize(&state, output, key, keylen);
}

/* HKDF-512 */

void hkdf512_expand(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen)
{
	hmac512_state state;
	uint8_t msg[SHA2_512_RATE] = { 0 };
	uint8_t otp[SHA2_512_HASH] = { 0 };
	size_t ctr;
	size_t i;
	size_t ioft;
	size_t mlen;
	size_t rmd;
	size_t slen;

	ctr = 0;
	slen = 0;

	while (outlen != 0)
	{
		hmac512_initialize(&state, key, keylen);
		mlen = infolen;
		ioft = 0;

		if (ctr != 0)
		{
			for (i = 0; i < SHA2_512_HASH; ++i)
			{
				msg[i] = otp[i];
			}

			slen = SHA2_512_HASH;

			if (infolen >= SHA2_512_HASH)
			{
				for (i = 0; i < SHA2_512_HASH; ++i)
				{
					msg[slen + i] = info[i];
				}

				hmac512_blockupdate(&state, msg, 1);
				mlen -= SHA2_512_HASH;
				ioft += SHA2_512_HASH;
				slen = 0;
			}

			while (mlen >= SHA2_512_RATE)
			{
				hmac512_blockupdate(&state, info + ioft, 1);
				ioft += SHA2_512_RATE;
				mlen -= SHA2_512_RATE;
			}

			for (i = 0; i < mlen; ++i)
			{
				msg[slen + i] = info[ioft + i];
			}

			++ctr;
			msg[slen + mlen] = (uint8_t)ctr;
			hmac512_finalize(&state, otp, msg, slen + mlen + 1);
		}
		else
		{
			while (mlen >= SHA2_512_RATE)
			{
				hmac512_blockupdate(&state, info + ioft, 1);
				ioft += SHA2_512_RATE;
				mlen -= SHA2_512_RATE;
			}

			for (i = 0; i < mlen; ++i)
			{
				msg[i] = info[ioft + i];
			}

			++ctr;
			msg[mlen] = (uint8_t)ctr;
			hmac512_finalize(&state, otp, msg, mlen + 1);
		}

		rmd = min((uint32_t)outlen, SHA2_512_HASH);

		for (i = 0; i < rmd; ++i)
		{
			output[i] = otp[i];
		}

		outlen -= rmd;
		output += rmd;
	}
}

void hkdf512_extract(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen)
{
	hmac512_state state;

	if (saltlen != 0)
	{
		hmac512_initialize(&state, salt, saltlen);
	}
	else
	{
		uint8_t tmp[HMAC_512_MAC] = { 0 };
		hmac512_initialize(&state, tmp, sizeof(tmp));
	}

	hmac512_finalize(&state, output, key, keylen);
}
