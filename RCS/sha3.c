#include "sha3.h"
#include "intutils.h"
#include "memutils.h"
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	include "intrinsics.h"
#	include <immintrin.h>
#endif

#define KECCAK_CSHAKE_DOMAIN_ID 0x04
#define KECCAK_KMAC_DOMAIN_ID 0x04
#define KECCAK_KPA_DOMAIN_ID 0x41
#define KECCAK_PERMUTATION_ROUNDS 24
#define KECCAK_SHA3_DOMAIN_ID 0x06
#define KECCAK_SHAKE_DOMAIN_ID 0x1F
#define KECCAK_STATE_BYTE_SIZE 200

/* keccak round constants */
static const uint64_t KECCAK_RC24[KECCAK_PERMUTATION_ROUNDS] =
{
	0x0000000000000001ULL,
	0x0000000000008082ULL,
	0x800000000000808aULL,
	0x8000000080008000ULL,
	0x000000000000808bULL,
	0x0000000080000001ULL,
	0x8000000080008081ULL,
	0x8000000000008009ULL,
	0x000000000000008aULL,
	0x0000000000000088ULL,
	0x0000000080008009ULL,
	0x000000008000000aULL,
	0x000000008000808bULL,
	0x800000000000008bULL,
	0x8000000000008089ULL,
	0x8000000000008003ULL,
	0x8000000000008002ULL,
	0x8000000000000080ULL,
	0x000000000000800aULL,
	0x800000008000000aULL,
	0x8000000080008081ULL,
	0x8000000000008080ULL,
	0x0000000080000001ULL,
	0x8000000080008008ULL
};

/* keccak */

static void keccak_absorb(uint64_t* state, keccak_rate rate, const uint8_t* input, size_t inplen, uint8_t domain)
{
	uint8_t msg[QSC_KECCAK_STATE_BYTE_SIZE];

	while (inplen >= (size_t)rate)
	{
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		qsc_memutils_xor((uint8_t*)state, input, rate);
#else
		for (size_t i = 0; i < rate / sizeof(uint64_t); ++i)
		{
			state[i] ^= qsc_intutils_le8to64((uint8_t*)(input + (sizeof(uint64_t) * i)));
		}
#endif
		qsc_keccak_permute(state);
		inplen -= rate;
		input += rate;
	}

	qsc_memutils_copy(msg, input, inplen);
	msg[inplen] = domain;
	qsc_memutils_clear((uint8_t*)(msg + inplen + 1), rate - inplen + 1);
	msg[rate - 1] |= 128U;

#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_xor((uint8_t*)state, msg, rate);
#else
	for (size_t i = 0; i < rate / 8; ++i)
	{
		state[i] ^= qsc_intutils_le8to64((uint8_t*)(msg + (8 * i)));
	}
#endif
}

static void keccak_fast_absorb(uint64_t* state, const uint8_t* input, size_t inplen)
{
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_xor((uint8_t*)state, input, inplen);
#else
	for (size_t i = 0; i < inplen / sizeof(uint64_t); ++i)
	{
		state[i] ^= qsc_intutils_le8to64((uint8_t*)(input + (sizeof(uint64_t) * i)));
	}
#endif
}

static size_t keccak_left_encode(uint8_t* buffer, size_t value)
{
	size_t i;
	size_t n;
	size_t v;

	for (v = value, n = 0; v != 0 && (n < sizeof(size_t)); ++n, v >>= 8) 
	{
	}

	if (n == 0)
	{
		n = 1;
	}

	for (i = 1; i <= n; ++i)
	{
		buffer[i] = (uint8_t)(value >> (8 * (n - i)));
	}

	buffer[0] = (uint8_t)n;

	return (size_t)n + 1;
}

static void qsc_keccak_permute_p1600(uint64_t* state, size_t rounds)
{
	assert(rounds % 2 == 0);

	uint64_t Aba; 
	uint64_t Abe; 
	uint64_t Abi; 
	uint64_t Abo;
	uint64_t Abu;
	uint64_t Aga; 
	uint64_t Age; 
	uint64_t Agi; 
	uint64_t Ago; 
	uint64_t Agu;
	uint64_t Aka;
	uint64_t Ake; 
	uint64_t Aki; 
	uint64_t Ako; 
	uint64_t Aku;
	uint64_t Ama; 
	uint64_t Ame; 
	uint64_t Ami; 
	uint64_t Amo; 
	uint64_t Amu;
	uint64_t Asa; 
	uint64_t Ase;
	uint64_t Asi;
	uint64_t Aso; 
	uint64_t Asu;
	uint64_t BCa; 
	uint64_t BCe; 
	uint64_t BCi; 
	uint64_t BCo; 
	uint64_t BCu;
	uint64_t Da;
	uint64_t De; 
	uint64_t Di; 
	uint64_t Do; 
	uint64_t Du;
	uint64_t Eba; 
	uint64_t Ebe; 
	uint64_t Ebi; 
	uint64_t Ebo;
	uint64_t Ebu;
	uint64_t Ega;
	uint64_t Ege;
	uint64_t Egi; 
	uint64_t Ego; 
	uint64_t Egu;
	uint64_t Eka; 
	uint64_t Eke; 
	uint64_t Eki;
	uint64_t Eko; 
	uint64_t Eku;
	uint64_t Ema; 
	uint64_t Eme; 
	uint64_t Emi; 
	uint64_t Emo; 
	uint64_t Emu;
	uint64_t Esa; 
	uint64_t Ese; 
	uint64_t Esi;
	uint64_t Eso; 
	uint64_t Esu;
	size_t i;

	/* copyFromState(A, state) */
	Aba = state[0];
	Abe = state[1];
	Abi = state[2];
	Abo = state[3];
	Abu = state[4];
	Aga = state[5];
	Age = state[6];
	Agi = state[7];
	Ago = state[8];
	Agu = state[9];
	Aka = state[10];
	Ake = state[11];
	Aki = state[12];
	Ako = state[13];
	Aku = state[14];
	Ama = state[15];
	Ame = state[16];
	Ami = state[17];
	Amo = state[18];
	Amu = state[19];
	Asa = state[20];
	Ase = state[21];
	Asi = state[22];
	Aso = state[23];
	Asu = state[24];

	for (i = 0; i < rounds; i += 2)
	{
		/* prepareTheta */
		BCa = Aba ^ Aga^Aka^Ama^Asa;
		BCe = Abe ^ Age^Ake^Ame^Ase;
		BCi = Abi ^ Agi^Aki^Ami^Asi;
		BCo = Abo ^ Ago^Ako^Amo^Aso;
		BCu = Abu ^ Agu^Aku^Amu^Asu;

		/* thetaRhoPiChiIotaPrepareTheta */
		Da = BCu ^ qsc_intutils_rotl64(BCe, 1);
		De = BCa ^ qsc_intutils_rotl64(BCi, 1);
		Di = BCe ^ qsc_intutils_rotl64(BCo, 1);
		Do = BCi ^ qsc_intutils_rotl64(BCu, 1);
		Du = BCo ^ qsc_intutils_rotl64(BCa, 1);

		Aba ^= Da;
		BCa = Aba;
		Age ^= De;
		BCe = qsc_intutils_rotl64(Age, 44);
		Aki ^= Di;
		BCi = qsc_intutils_rotl64(Aki, 43);
		Amo ^= Do;
		BCo = qsc_intutils_rotl64(Amo, 21);
		Asu ^= Du;
		BCu = qsc_intutils_rotl64(Asu, 14);
		Eba = BCa ^ ((~BCe)&  BCi);
		Eba ^= KECCAK_RC24[i];
		Ebe = BCe ^ ((~BCi)&  BCo);
		Ebi = BCi ^ ((~BCo)&  BCu);
		Ebo = BCo ^ ((~BCu)&  BCa);
		Ebu = BCu ^ ((~BCa)&  BCe);

		Abo ^= Do;
		BCa = qsc_intutils_rotl64(Abo, 28);
		Agu ^= Du;
		BCe = qsc_intutils_rotl64(Agu, 20);
		Aka ^= Da;
		BCi = qsc_intutils_rotl64(Aka, 3);
		Ame ^= De;
		BCo = qsc_intutils_rotl64(Ame, 45);
		Asi ^= Di;
		BCu = qsc_intutils_rotl64(Asi, 61);
		Ega = BCa ^ ((~BCe)&  BCi);
		Ege = BCe ^ ((~BCi)&  BCo);
		Egi = BCi ^ ((~BCo)&  BCu);
		Ego = BCo ^ ((~BCu)&  BCa);
		Egu = BCu ^ ((~BCa)&  BCe);

		Abe ^= De;
		BCa = qsc_intutils_rotl64(Abe, 1);
		Agi ^= Di;
		BCe = qsc_intutils_rotl64(Agi, 6);
		Ako ^= Do;
		BCi = qsc_intutils_rotl64(Ako, 25);
		Amu ^= Du;
		BCo = qsc_intutils_rotl64(Amu, 8);
		Asa ^= Da;
		BCu = qsc_intutils_rotl64(Asa, 18);
		Eka = BCa ^ ((~BCe)&  BCi);
		Eke = BCe ^ ((~BCi)&  BCo);
		Eki = BCi ^ ((~BCo)&  BCu);
		Eko = BCo ^ ((~BCu)&  BCa);
		Eku = BCu ^ ((~BCa)&  BCe);

		Abu ^= Du;
		BCa = qsc_intutils_rotl64(Abu, 27);
		Aga ^= Da;
		BCe = qsc_intutils_rotl64(Aga, 36);
		Ake ^= De;
		BCi = qsc_intutils_rotl64(Ake, 10);
		Ami ^= Di;
		BCo = qsc_intutils_rotl64(Ami, 15);
		Aso ^= Do;
		BCu = qsc_intutils_rotl64(Aso, 56);
		Ema = BCa ^ ((~BCe)&  BCi);
		Eme = BCe ^ ((~BCi)&  BCo);
		Emi = BCi ^ ((~BCo)&  BCu);
		Emo = BCo ^ ((~BCu)&  BCa);
		Emu = BCu ^ ((~BCa)&  BCe);

		Abi ^= Di;
		BCa = qsc_intutils_rotl64(Abi, 62);
		Ago ^= Do;
		BCe = qsc_intutils_rotl64(Ago, 55);
		Aku ^= Du;
		BCi = qsc_intutils_rotl64(Aku, 39);
		Ama ^= Da;
		BCo = qsc_intutils_rotl64(Ama, 41);
		Ase ^= De;
		BCu = qsc_intutils_rotl64(Ase, 2);
		Esa = BCa ^ ((~BCe)&  BCi);
		Ese = BCe ^ ((~BCi)&  BCo);
		Esi = BCi ^ ((~BCo)&  BCu);
		Eso = BCo ^ ((~BCu)&  BCa);
		Esu = BCu ^ ((~BCa)&  BCe);

		/* prepareTheta */
		BCa = Eba ^ Ega^Eka^Ema^Esa;
		BCe = Ebe ^ Ege^Eke^Eme^Ese;
		BCi = Ebi ^ Egi^Eki^Emi^Esi;
		BCo = Ebo ^ Ego^Eko^Emo^Eso;
		BCu = Ebu ^ Egu^Eku^Emu^Esu;

		/* thetaRhoPiChiIotaPrepareTheta */
		Da = BCu ^ qsc_intutils_rotl64(BCe, 1);
		De = BCa ^ qsc_intutils_rotl64(BCi, 1);
		Di = BCe ^ qsc_intutils_rotl64(BCo, 1);
		Do = BCi ^ qsc_intutils_rotl64(BCu, 1);
		Du = BCo ^ qsc_intutils_rotl64(BCa, 1);

		Eba ^= Da;
		BCa = Eba;
		Ege ^= De;
		BCe = qsc_intutils_rotl64(Ege, 44);
		Eki ^= Di;
		BCi = qsc_intutils_rotl64(Eki, 43);
		Emo ^= Do;
		BCo = qsc_intutils_rotl64(Emo, 21);
		Esu ^= Du;
		BCu = qsc_intutils_rotl64(Esu, 14);
		Aba = BCa ^ ((~BCe)&  BCi);
		Aba ^= KECCAK_RC24[i + 1];
		Abe = BCe ^ ((~BCi)&  BCo);
		Abi = BCi ^ ((~BCo)&  BCu);
		Abo = BCo ^ ((~BCu)&  BCa);
		Abu = BCu ^ ((~BCa)&  BCe);

		Ebo ^= Do;
		BCa = qsc_intutils_rotl64(Ebo, 28);
		Egu ^= Du;
		BCe = qsc_intutils_rotl64(Egu, 20);
		Eka ^= Da;
		BCi = qsc_intutils_rotl64(Eka, 3);
		Eme ^= De;
		BCo = qsc_intutils_rotl64(Eme, 45);
		Esi ^= Di;
		BCu = qsc_intutils_rotl64(Esi, 61);
		Aga = BCa ^ ((~BCe)&  BCi);
		Age = BCe ^ ((~BCi)&  BCo);
		Agi = BCi ^ ((~BCo)&  BCu);
		Ago = BCo ^ ((~BCu)&  BCa);
		Agu = BCu ^ ((~BCa)&  BCe);

		Ebe ^= De;
		BCa = qsc_intutils_rotl64(Ebe, 1);
		Egi ^= Di;
		BCe = qsc_intutils_rotl64(Egi, 6);
		Eko ^= Do;
		BCi = qsc_intutils_rotl64(Eko, 25);
		Emu ^= Du;
		BCo = qsc_intutils_rotl64(Emu, 8);
		Esa ^= Da;
		BCu = qsc_intutils_rotl64(Esa, 18);
		Aka = BCa ^ ((~BCe)&  BCi);
		Ake = BCe ^ ((~BCi)&  BCo);
		Aki = BCi ^ ((~BCo)&  BCu);
		Ako = BCo ^ ((~BCu)&  BCa);
		Aku = BCu ^ ((~BCa)&  BCe);

		Ebu ^= Du;
		BCa = qsc_intutils_rotl64(Ebu, 27);
		Ega ^= Da;
		BCe = qsc_intutils_rotl64(Ega, 36);
		Eke ^= De;
		BCi = qsc_intutils_rotl64(Eke, 10);
		Emi ^= Di;
		BCo = qsc_intutils_rotl64(Emi, 15);
		Eso ^= Do;
		BCu = qsc_intutils_rotl64(Eso, 56);
		Ama = BCa ^ ((~BCe)&  BCi);
		Ame = BCe ^ ((~BCi)&  BCo);
		Ami = BCi ^ ((~BCo)&  BCu);
		Amo = BCo ^ ((~BCu)&  BCa);
		Amu = BCu ^ ((~BCa)&  BCe);

		Ebi ^= Di;
		BCa = qsc_intutils_rotl64(Ebi, 62);
		Ego ^= Do;
		BCe = qsc_intutils_rotl64(Ego, 55);
		Eku ^= Du;
		BCi = qsc_intutils_rotl64(Eku, 39);
		Ema ^= Da;
		BCo = qsc_intutils_rotl64(Ema, 41);
		Ese ^= De;
		BCu = qsc_intutils_rotl64(Ese, 2);
		Asa = BCa ^ ((~BCe)&  BCi);
		Ase = BCe ^ ((~BCi)&  BCo);
		Asi = BCi ^ ((~BCo)&  BCu);
		Aso = BCo ^ ((~BCu)&  BCa);
		Asu = BCu ^ ((~BCa)&  BCe);
	}

	/* copy to state */
	state[0] = Aba;
	state[1] = Abe;
	state[2] = Abi;
	state[3] = Abo;
	state[4] = Abu;
	state[5] = Aga;
	state[6] = Age;
	state[7] = Agi;
	state[8] = Ago;
	state[9] = Agu;
	state[10] = Aka;
	state[11] = Ake;
	state[12] = Aki;
	state[13] = Ako;
	state[14] = Aku;
	state[15] = Ama;
	state[16] = Ame;
	state[17] = Ami;
	state[18] = Amo;
	state[19] = Amu;
	state[20] = Asa;
	state[21] = Ase;
	state[22] = Asi;
	state[23] = Aso;
	state[24] = Asu;
}

#if defined(QSC_KECCAK_UNROLLED_PERMUTATION)

static void qsc_keccak_permute_p1600(uint64_t* state)
{
	uint64_t Aba;
	uint64_t Abe;
	uint64_t Abi;
	uint64_t Abo;
	uint64_t Abu;
	uint64_t Aga;
	uint64_t Age;
	uint64_t Agi;
	uint64_t Ago;
	uint64_t Agu;
	uint64_t Aka;
	uint64_t Ake;
	uint64_t Aki;
	uint64_t Ako;
	uint64_t Aku;
	uint64_t Ama;
	uint64_t Ame;
	uint64_t Ami;
	uint64_t Amo;
	uint64_t Amu;
	uint64_t Asa;
	uint64_t Ase;
	uint64_t Asi;
	uint64_t Aso;
	uint64_t Asu;
	uint64_t Ca;
	uint64_t Ce;
	uint64_t Ci;
	uint64_t Co;
	uint64_t Cu;
	uint64_t Da;
	uint64_t De;
	uint64_t Di;
	uint64_t Do;
	uint64_t Du;
	uint64_t Eba;
	uint64_t Ebe;
	uint64_t Ebi;
	uint64_t Ebo;
	uint64_t Ebu;
	uint64_t Ega;
	uint64_t Ege;
	uint64_t Egi;
	uint64_t Ego;
	uint64_t Egu;
	uint64_t Eka;
	uint64_t Eke;
	uint64_t Eki;
	uint64_t Eko;
	uint64_t Eku;
	uint64_t Ema;
	uint64_t Eme;
	uint64_t Emi;
	uint64_t Emo;
	uint64_t Emu;
	uint64_t Esa;
	uint64_t Ese;
	uint64_t Esi;
	uint64_t Eso;
	uint64_t Esu;

	Aba = state[0];
	Abe = state[1];
	Abi = state[2];
	Abo = state[3];
	Abu = state[4];
	Aga = state[5];
	Age = state[6];
	Agi = state[7];
	Ago = state[8];
	Agu = state[9];
	Aka = state[10];
	Ake = state[11];
	Aki = state[12];
	Ako = state[13];
	Aku = state[14];
	Ama = state[15];
	Ame = state[16];
	Ami = state[17];
	Amo = state[18];
	Amu = state[19];
	Asa = state[20];
	Ase = state[21];
	Asi = state[22];
	Aso = state[23];
	Asu = state[24];

	/* round 1 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000000000001ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 2 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000000008082ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 3 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x800000000000808AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 4 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000080008000ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 5 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000808BULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 6 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000080000001ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 7 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000080008081ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 8 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008009ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 9 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000008AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 10 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000000000088ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 11 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000080008009ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 12 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x000000008000000AULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 13 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000008000808BULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 14 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x800000000000008BULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 15 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000000008089ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 16 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008003ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 17 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000000008002ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 18 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000000080ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 19 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000800AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 20 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x800000008000000AULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 21 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000080008081ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 22 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008080ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);
	/* round 23 */
	Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
	Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
	Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
	Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
	Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = qsc_intutils_rotl64(Age, 44);
	Aki ^= Di;
	Ci = qsc_intutils_rotl64(Aki, 43);
	Amo ^= Do;
	Co = qsc_intutils_rotl64(Amo, 21);
	Asu ^= Du;
	Cu = qsc_intutils_rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000080000001ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = qsc_intutils_rotl64(Abo, 28);
	Agu ^= Du;
	Ce = qsc_intutils_rotl64(Agu, 20);
	Aka ^= Da;
	Ci = qsc_intutils_rotl64(Aka, 3);
	Ame ^= De;
	Co = qsc_intutils_rotl64(Ame, 45);
	Asi ^= Di;
	Cu = qsc_intutils_rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = qsc_intutils_rotl64(Abe, 1);
	Agi ^= Di;
	Ce = qsc_intutils_rotl64(Agi, 6);
	Ako ^= Do;
	Ci = qsc_intutils_rotl64(Ako, 25);
	Amu ^= Du;
	Co = qsc_intutils_rotl64(Amu, 8);
	Asa ^= Da;
	Cu = qsc_intutils_rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = qsc_intutils_rotl64(Abu, 27);
	Aga ^= Da;
	Ce = qsc_intutils_rotl64(Aga, 36);
	Ake ^= De;
	Ci = qsc_intutils_rotl64(Ake, 10);
	Ami ^= Di;
	Co = qsc_intutils_rotl64(Ami, 15);
	Aso ^= Do;
	Cu = qsc_intutils_rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = qsc_intutils_rotl64(Abi, 62);
	Ago ^= Do;
	Ce = qsc_intutils_rotl64(Ago, 55);
	Aku ^= Du;
	Ci = qsc_intutils_rotl64(Aku, 39);
	Ama ^= Da;
	Co = qsc_intutils_rotl64(Ama, 41);
	Ase ^= De;
	Cu = qsc_intutils_rotl64(Ase, 2);
	Esa = Ca ^ ((~Ce) & Ci);
	Ese = Ce ^ ((~Ci) & Co);
	Esi = Ci ^ ((~Co) & Cu);
	Eso = Co ^ ((~Cu) & Ca);
	Esu = Cu ^ ((~Ca) & Ce);
	/* round 24 */
	Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
	Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
	Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
	Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
	Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
	Da = Cu ^ qsc_intutils_rotl64(Ce, 1);
	De = Ca ^ qsc_intutils_rotl64(Ci, 1);
	Di = Ce ^ qsc_intutils_rotl64(Co, 1);
	Do = Ci ^ qsc_intutils_rotl64(Cu, 1);
	Du = Co ^ qsc_intutils_rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = qsc_intutils_rotl64(Ege, 44);
	Eki ^= Di;
	Ci = qsc_intutils_rotl64(Eki, 43);
	Emo ^= Do;
	Co = qsc_intutils_rotl64(Emo, 21);
	Esu ^= Du;
	Cu = qsc_intutils_rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000080008008ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = qsc_intutils_rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = qsc_intutils_rotl64(Egu, 20);
	Eka ^= Da;
	Ci = qsc_intutils_rotl64(Eka, 3);
	Eme ^= De;
	Co = qsc_intutils_rotl64(Eme, 45);
	Esi ^= Di;
	Cu = qsc_intutils_rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = qsc_intutils_rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = qsc_intutils_rotl64(Egi, 6);
	Eko ^= Do;
	Ci = qsc_intutils_rotl64(Eko, 25);
	Emu ^= Du;
	Co = qsc_intutils_rotl64(Emu, 8);
	Esa ^= Da;
	Cu = qsc_intutils_rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = qsc_intutils_rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = qsc_intutils_rotl64(Ega, 36);
	Eke ^= De;
	Ci = qsc_intutils_rotl64(Eke, 10);
	Emi ^= Di;
	Co = qsc_intutils_rotl64(Emi, 15);
	Eso ^= Do;
	Cu = qsc_intutils_rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = qsc_intutils_rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = qsc_intutils_rotl64(Ego, 55);
	Eku ^= Du;
	Ci = qsc_intutils_rotl64(Eku, 39);
	Ema ^= Da;
	Co = qsc_intutils_rotl64(Ema, 41);
	Ese ^= De;
	Cu = qsc_intutils_rotl64(Ese, 2);
	Asa = Ca ^ ((~Ce) & Ci);
	Ase = Ce ^ ((~Ci) & Co);
	Asi = Ci ^ ((~Co) & Cu);
	Aso = Co ^ ((~Cu) & Ca);
	Asu = Cu ^ ((~Ca) & Ce);

	state[0] = Aba;
	state[1] = Abe;
	state[2] = Abi;
	state[3] = Abo;
	state[4] = Abu;
	state[5] = Aga;
	state[6] = Age;
	state[7] = Agi;
	state[8] = Ago;
	state[9] = Agu;
	state[10] = Aka;
	state[11] = Ake;
	state[12] = Aki;
	state[13] = Ako;
	state[14] = Aku;
	state[15] = Ama;
	state[16] = Ame;
	state[17] = Ami;
	state[18] = Amo;
	state[19] = Amu;
	state[20] = Asa;
	state[21] = Ase;
	state[22] = Asi;
	state[23] = Aso;
	state[24] = Asu;
}

#endif

static size_t keccak_right_encode(uint8_t* buffer, size_t value)
{
	size_t i;
	size_t n;
	size_t v;

	for (v = value, n = 0; v != 0 && (n < sizeof(size_t)); ++n, v >>= 8) 
	{
	}

	if (n == 0)
	{
		n = 1;
	}

	for (i = 1; i <= n; ++i)
	{
		buffer[i - 1] = (uint8_t)(value >> (8 * (n - i)));
	}

	buffer[n] = (uint8_t)n;

	return (size_t)n + 1;
}

static void keccak_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks, keccak_rate rate)
{
	while (nblocks > 0)
	{
		qsc_keccak_permute(state);

#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		qsc_memutils_copy(output, (uint8_t*)state, rate);
#else
		for (size_t i = 0; i < (rate >> 3); ++i)
		{
			qsc_intutils_le64to8((uint8_t*)(output + sizeof(uint64_t) * i), state[i]);
		}
#endif
		output += rate;
		nblocks--;
	}
}

static void keccak_update(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);

	if (msglen != 0)
	{
		if (ctx->position != 0 && (ctx->position + msglen >= (size_t)rate))
		{
			const size_t RMDLEN = rate - ctx->position;

			if (RMDLEN != 0)
			{
				qsc_memutils_copy((uint8_t*)(ctx->buffer + ctx->position), message, RMDLEN);
			}

			keccak_fast_absorb(ctx->state, ctx->buffer, (size_t)rate);
			qsc_keccak_permute(ctx->state);
			ctx->position = 0;
			message += RMDLEN;
			msglen -= RMDLEN;
		}

		/* sequential loop through blocks */
		while (msglen >= (size_t)rate)
		{
			keccak_fast_absorb(ctx->state, message, rate);
			qsc_keccak_permute(ctx->state);
			message += rate;
			msglen -= rate;
		}

		/* store unaligned bytes */
		if (msglen != 0)
		{
			qsc_memutils_copy((uint8_t*)(ctx->buffer + ctx->position), message, msglen);
			ctx->position += msglen;
		}
	}
}

#if defined(QSC_SYSTEM_HAS_AVX512)
void qsc_keccak_permute_p8x1600(__m512i state[QSC_KECCAK_STATE_SIZE], size_t rounds)
{
	assert(rounds % 2 == 0);

	__m512i a[25] = { 0 };
	__m512i c[5] = { 0 };
	__m512i d[5] = { 0 };
	__m512i e[25] = { 0 };
	size_t i;
	
	for (i = 0; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		a[i] = state[i];
	}

	for (i = 0; i < rounds; i += 2)
	{
		// round n
		c[0] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a[0], a[5]), _mm512_xor_si512(a[10], a[15])), a[20]);
		c[1] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a[1], a[6]), _mm512_xor_si512(a[11], a[16])), a[21]);
		c[2] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a[2], a[7]), _mm512_xor_si512(a[12], a[17])), a[22]);
		c[3] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a[3], a[8]), _mm512_xor_si512(a[13], a[18])), a[23]);
		c[4] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a[4], a[9]), _mm512_xor_si512(a[14], a[19])), a[24]);
		d[0] = _mm512_xor_si512(c[4], _mm512_or_si512(_mm512_slli_epi64(c[1], 1), _mm512_srli_epi64(c[1], 64 - 1)));
		d[1] = _mm512_xor_si512(c[0], _mm512_or_si512(_mm512_slli_epi64(c[2], 1), _mm512_srli_epi64(c[2], 64 - 1)));
		d[2] = _mm512_xor_si512(c[1], _mm512_or_si512(_mm512_slli_epi64(c[3], 1), _mm512_srli_epi64(c[3], 64 - 1)));
		d[3] = _mm512_xor_si512(c[2], _mm512_or_si512(_mm512_slli_epi64(c[4], 1), _mm512_srli_epi64(c[4], 64 - 1)));
		d[4] = _mm512_xor_si512(c[3], _mm512_or_si512(_mm512_slli_epi64(c[0], 1), _mm512_srli_epi64(c[0], 64 - 1)));
		a[0] = _mm512_xor_si512(a[0], d[0]);
		c[0] = a[0];
		a[6] = _mm512_xor_si512(a[6], d[1]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(a[6], 44), _mm512_srli_epi64(a[6], 64 - 44));
		a[12] = _mm512_xor_si512(a[12], d[2]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(a[12], 43), _mm512_srli_epi64(a[12], 64 - 43));
		a[18] = _mm512_xor_si512(a[18], d[3]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(a[18], 21), _mm512_srli_epi64(a[18], 64 - 21));
		a[24] = _mm512_xor_si512(a[24], d[4]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(a[24], 14), _mm512_srli_epi64(a[24], 64 - 14));
		e[0] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		e[0] = _mm512_xor_si512(e[0], _mm512_set1_epi64(KECCAK_RC24[i]));
		e[1] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		e[2] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		e[3] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		e[4] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		a[3] = _mm512_xor_si512(a[3], d[3]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(a[3], 28), _mm512_srli_epi64(a[3], 64 - 28));
		a[9] = _mm512_xor_si512(a[9], d[4]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(a[9], 20), _mm512_srli_epi64(a[9], 64 - 20));
		a[10] = _mm512_xor_si512(a[10], d[0]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(a[10], 3), _mm512_srli_epi64(a[10], 64 - 3));
		a[16] = _mm512_xor_si512(a[16], d[1]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(a[16], 45), _mm512_srli_epi64(a[16], 64 - 45));
		a[22] = _mm512_xor_si512(a[22], d[2]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(a[22], 61), _mm512_srli_epi64(a[22], 64 - 61));
		e[5] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		e[6] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		e[7] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		e[8] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		e[9] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		a[1] = _mm512_xor_si512(a[1], d[1]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(a[1], 1), _mm512_srli_epi64(a[1], 64 - 1));
		a[7] = _mm512_xor_si512(a[7], d[2]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(a[7], 6), _mm512_srli_epi64(a[7], 64 - 6));
		a[13] = _mm512_xor_si512(a[13], d[3]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(a[13], 25), _mm512_srli_epi64(a[13], 64 - 25));
		a[19] = _mm512_xor_si512(a[19], d[4]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(a[19], 8), _mm512_srli_epi64(a[19], 64 - 8));
		a[20] = _mm512_xor_si512(a[20], d[0]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(a[20], 18), _mm512_srli_epi64(a[20], 64 - 18));
		e[10] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		e[11] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		e[12] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		e[13] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		e[14] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		a[4] = _mm512_xor_si512(a[4], d[4]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(a[4], 27), _mm512_srli_epi64(a[4], 64 - 27));
		a[5] = _mm512_xor_si512(a[5], d[0]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(a[5], 36), _mm512_srli_epi64(a[5], 64 - 36));
		a[11] = _mm512_xor_si512(a[11], d[1]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(a[11], 10), _mm512_srli_epi64(a[11], 64 - 10));
		a[17] = _mm512_xor_si512(a[17], d[2]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(a[17], 15), _mm512_srli_epi64(a[17], 64 - 15));
		a[23] = _mm512_xor_si512(a[23], d[3]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(a[23], 56), _mm512_srli_epi64(a[23], 64 - 56));
		e[15] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		e[16] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		e[17] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		e[18] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		e[19] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		a[2] = _mm512_xor_si512(a[2], d[2]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(a[2], 62), _mm512_srli_epi64(a[2], 64 - 62));
		a[8] = _mm512_xor_si512(a[8], d[3]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(a[8], 55), _mm512_srli_epi64(a[8], 64 - 55));
		a[14] = _mm512_xor_si512(a[14], d[4]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(a[14], 39), _mm512_srli_epi64(a[14], 64 - 39));
		a[15] = _mm512_xor_si512(a[15], d[0]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(a[15], 41), _mm512_srli_epi64(a[15], 64 - 41));
		a[21] = _mm512_xor_si512(a[21], d[1]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(a[21], 2), _mm512_srli_epi64(a[21], 64 - 2));
		e[20] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		e[21] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		e[22] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		e[23] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		e[24] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));

		// round n + 1
		c[0] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e[0], e[5]), _mm512_xor_si512(e[10], e[15])), e[20]);
		c[1] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e[1], e[6]), _mm512_xor_si512(e[11], e[16])), e[21]);
		c[2] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e[2], e[7]), _mm512_xor_si512(e[12], e[17])), e[22]);
		c[3] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e[3], e[8]), _mm512_xor_si512(e[13], e[18])), e[23]);
		c[4] = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e[4], e[9]), _mm512_xor_si512(e[14], e[19])), e[24]);
		d[0] = _mm512_xor_si512(c[4], _mm512_or_si512(_mm512_slli_epi64(c[1], 1), _mm512_srli_epi64(c[1], 64 - 1)));
		d[1] = _mm512_xor_si512(c[0], _mm512_or_si512(_mm512_slli_epi64(c[2], 1), _mm512_srli_epi64(c[2], 64 - 1)));
		d[2] = _mm512_xor_si512(c[1], _mm512_or_si512(_mm512_slli_epi64(c[3], 1), _mm512_srli_epi64(c[3], 64 - 1)));
		d[3] = _mm512_xor_si512(c[2], _mm512_or_si512(_mm512_slli_epi64(c[4], 1), _mm512_srli_epi64(c[4], 64 - 1)));
		d[4] = _mm512_xor_si512(c[3], _mm512_or_si512(_mm512_slli_epi64(c[0], 1), _mm512_srli_epi64(c[0], 64 - 1)));
		e[0] = _mm512_xor_si512(e[0], d[0]);
		c[0] = e[0];
		e[6] = _mm512_xor_si512(e[6], d[1]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(e[6], 44), _mm512_srli_epi64(e[6], 64 - 44));
		e[12] = _mm512_xor_si512(e[12], d[2]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(e[12], 43), _mm512_srli_epi64(e[12], 64 - 43));
		e[18] = _mm512_xor_si512(e[18], d[3]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(e[18], 21), _mm512_srli_epi64(e[18], 64 - 21));
		e[24] = _mm512_xor_si512(e[24], d[4]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(e[24], 14), _mm512_srli_epi64(e[24], 64 - 14));
		a[0] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		a[0] = _mm512_xor_si512(a[0], _mm512_set1_epi64(KECCAK_RC24[i + 1]));
		a[1] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		a[2] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		a[3] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		a[4] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		e[3] = _mm512_xor_si512(e[3], d[3]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(e[3], 28), _mm512_srli_epi64(e[3], 64 - 28));
		e[9] = _mm512_xor_si512(e[9], d[4]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(e[9], 20), _mm512_srli_epi64(e[9], 64 - 20));
		e[10] = _mm512_xor_si512(e[10], d[0]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(e[10], 3), _mm512_srli_epi64(e[10], 64 - 3));
		e[16] = _mm512_xor_si512(e[16], d[1]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(e[16], 45), _mm512_srli_epi64(e[16], 64 - 45));
		e[22] = _mm512_xor_si512(e[22], d[2]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(e[22], 61), _mm512_srli_epi64(e[22], 64 - 61));
		a[5] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		a[6] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		a[7] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		a[8] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		a[9] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		e[1] = _mm512_xor_si512(e[1], d[1]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(e[1], 1), _mm512_srli_epi64(e[1], 64 - 1));
		e[7] = _mm512_xor_si512(e[7], d[2]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(e[7], 6), _mm512_srli_epi64(e[7], 64 - 6));
		e[13] = _mm512_xor_si512(e[13], d[3]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(e[13], 25), _mm512_srli_epi64(e[13], 64 - 25));
		e[19] = _mm512_xor_si512(e[19], d[4]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(e[19], 8), _mm512_srli_epi64(e[19], 64 - 8));
		e[20] = _mm512_xor_si512(e[20], d[0]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(e[20], 18), _mm512_srli_epi64(e[20], 64 - 18));
		a[10] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		a[11] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		a[12] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		a[13] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		a[14] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		e[4] = _mm512_xor_si512(e[4], d[4]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(e[4], 27), _mm512_srli_epi64(e[4], 64 - 27));
		e[5] = _mm512_xor_si512(e[5], d[0]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(e[5], 36), _mm512_srli_epi64(e[5], 64 - 36));
		e[11] = _mm512_xor_si512(e[11], d[1]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(e[11], 10), _mm512_srli_epi64(e[11], 64 - 10));
		e[17] = _mm512_xor_si512(e[17], d[2]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(e[17], 15), _mm512_srli_epi64(e[17], 64 - 15));
		e[23] = _mm512_xor_si512(e[23], d[3]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(e[23], 56), _mm512_srli_epi64(e[23], 64 - 56));
		a[15] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		a[16] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		a[17] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		a[18] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		a[19] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
		e[2] = _mm512_xor_si512(e[2], d[2]);
		c[0] = _mm512_or_si512(_mm512_slli_epi64(e[2], 62), _mm512_srli_epi64(e[2], 64 - 62));
		e[8] = _mm512_xor_si512(e[8], d[3]);
		c[1] = _mm512_or_si512(_mm512_slli_epi64(e[8], 55), _mm512_srli_epi64(e[8], 64 - 55));
		e[14] = _mm512_xor_si512(e[14], d[4]);
		c[2] = _mm512_or_si512(_mm512_slli_epi64(e[14], 39), _mm512_srli_epi64(e[14], 64 - 39));
		e[15] = _mm512_xor_si512(e[15], d[0]);
		c[3] = _mm512_or_si512(_mm512_slli_epi64(e[15], 41), _mm512_srli_epi64(e[15], 64 - 41));
		e[21] = _mm512_xor_si512(e[21], d[1]);
		c[4] = _mm512_or_si512(_mm512_slli_epi64(e[21], 2), _mm512_srli_epi64(e[21], 64 - 2));
		a[20] = _mm512_xor_si512(c[0], _mm512_and_si512(_mm512_xor_epi64(c[1], _mm512_set1_epi64(-1)), c[2]));
		a[21] = _mm512_xor_si512(c[1], _mm512_and_si512(_mm512_xor_epi64(c[2], _mm512_set1_epi64(-1)), c[3]));
		a[22] = _mm512_xor_si512(c[2], _mm512_and_si512(_mm512_xor_epi64(c[3], _mm512_set1_epi64(-1)), c[4]));
		a[23] = _mm512_xor_si512(c[3], _mm512_and_si512(_mm512_xor_epi64(c[4], _mm512_set1_epi64(-1)), c[0]));
		a[24] = _mm512_xor_si512(c[4], _mm512_and_si512(_mm512_xor_epi64(c[0], _mm512_set1_epi64(-1)), c[1]));
	}

	for (i = 0; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		state[i] = a[i];
	}
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
void qsc_keccak_permute_p4x1600(__m256i state[QSC_KECCAK_STATE_SIZE], size_t rounds)
{
	assert(rounds % 2 == 0);

	__m256i a[25] = { 0 };
	__m256i c[5] = { 0 };
	__m256i d[5] = { 0 };
	__m256i e[25] = { 0 };
	size_t i;

	for (i = 0; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		a[i] = state[i];
	}

	for (i = 0; i < rounds; i += 2)
	{
		// round n
		c[0] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a[0], a[5]), _mm256_xor_si256(a[10], a[15])), a[20]);
		c[1] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a[1], a[6]), _mm256_xor_si256(a[11], a[16])), a[21]);
		c[2] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a[2], a[7]), _mm256_xor_si256(a[12], a[17])), a[22]);
		c[3] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a[3], a[8]), _mm256_xor_si256(a[13], a[18])), a[23]);
		c[4] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a[4], a[9]), _mm256_xor_si256(a[14], a[19])), a[24]);
		d[0] = _mm256_xor_si256(c[4], _mm256_or_si256(_mm256_slli_epi64(c[1], 1), _mm256_srli_epi64(c[1], 64 - 1)));
		d[1] = _mm256_xor_si256(c[0], _mm256_or_si256(_mm256_slli_epi64(c[2], 1), _mm256_srli_epi64(c[2], 64 - 1)));
		d[2] = _mm256_xor_si256(c[1], _mm256_or_si256(_mm256_slli_epi64(c[3], 1), _mm256_srli_epi64(c[3], 64 - 1)));
		d[3] = _mm256_xor_si256(c[2], _mm256_or_si256(_mm256_slli_epi64(c[4], 1), _mm256_srli_epi64(c[4], 64 - 1)));
		d[4] = _mm256_xor_si256(c[3], _mm256_or_si256(_mm256_slli_epi64(c[0], 1), _mm256_srli_epi64(c[0], 64 - 1)));
		a[0] = _mm256_xor_si256(a[0], d[0]);
		c[0] = a[0];
		a[6] = _mm256_xor_si256(a[6], d[1]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(a[6], 44), _mm256_srli_epi64(a[6], 64 - 44));
		a[12] = _mm256_xor_si256(a[12], d[2]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(a[12], 43), _mm256_srli_epi64(a[12], 64 - 43));
		a[18] = _mm256_xor_si256(a[18], d[3]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(a[18], 21), _mm256_srli_epi64(a[18], 64 - 21));
		a[24] = _mm256_xor_si256(a[24], d[4]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(a[24], 14), _mm256_srli_epi64(a[24], 64 - 14));
		e[0] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		e[0] = _mm256_xor_si256(e[0], _mm256_set1_epi64x(KECCAK_RC24[i]));
		e[1] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		e[2] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		e[3] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		e[4] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		a[3] = _mm256_xor_si256(a[3], d[3]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(a[3], 28), _mm256_srli_epi64(a[3], 64 - 28));
		a[9] = _mm256_xor_si256(a[9], d[4]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(a[9], 20), _mm256_srli_epi64(a[9], 64 - 20));
		a[10] = _mm256_xor_si256(a[10], d[0]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(a[10], 3), _mm256_srli_epi64(a[10], 64 - 3));
		a[16] = _mm256_xor_si256(a[16], d[1]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(a[16], 45), _mm256_srli_epi64(a[16], 64 - 45));
		a[22] = _mm256_xor_si256(a[22], d[2]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(a[22], 61), _mm256_srli_epi64(a[22], 64 - 61));
		e[5] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		e[6] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		e[7] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		e[8] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		e[9] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		a[1] = _mm256_xor_si256(a[1], d[1]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(a[1], 1), _mm256_srli_epi64(a[1], 64 - 1));
		a[7] = _mm256_xor_si256(a[7], d[2]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(a[7], 6), _mm256_srli_epi64(a[7], 64 - 6));
		a[13] = _mm256_xor_si256(a[13], d[3]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(a[13], 25), _mm256_srli_epi64(a[13], 64 - 25));
		a[19] = _mm256_xor_si256(a[19], d[4]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(a[19], 8), _mm256_srli_epi64(a[19], 64 - 8));
		a[20] = _mm256_xor_si256(a[20], d[0]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(a[20], 18), _mm256_srli_epi64(a[20], 64 - 18));
		e[10] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		e[11] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		e[12] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		e[13] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		e[14] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		a[4] = _mm256_xor_si256(a[4], d[4]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(a[4], 27), _mm256_srli_epi64(a[4], 64 - 27));
		a[5] = _mm256_xor_si256(a[5], d[0]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(a[5], 36), _mm256_srli_epi64(a[5], 64 - 36));
		a[11] = _mm256_xor_si256(a[11], d[1]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(a[11], 10), _mm256_srli_epi64(a[11], 64 - 10));
		a[17] = _mm256_xor_si256(a[17], d[2]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(a[17], 15), _mm256_srli_epi64(a[17], 64 - 15));
		a[23] = _mm256_xor_si256(a[23], d[3]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(a[23], 56), _mm256_srli_epi64(a[23], 64 - 56));
		e[15] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		e[16] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		e[17] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		e[18] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		e[19] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		a[2] = _mm256_xor_si256(a[2], d[2]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(a[2], 62), _mm256_srli_epi64(a[2], 64 - 62));
		a[8] = _mm256_xor_si256(a[8], d[3]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(a[8], 55), _mm256_srli_epi64(a[8], 64 - 55));
		a[14] = _mm256_xor_si256(a[14], d[4]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(a[14], 39), _mm256_srli_epi64(a[14], 64 - 39));
		a[15] = _mm256_xor_si256(a[15], d[0]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(a[15], 41), _mm256_srli_epi64(a[15], 64 - 41));
		a[21] = _mm256_xor_si256(a[21], d[1]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(a[21], 2), _mm256_srli_epi64(a[21], 64 - 2));
		e[20] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		e[21] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		e[22] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		e[23] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		e[24] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));

		// round n + 1
		c[0] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e[0], e[5]), _mm256_xor_si256(e[10], e[15])), e[20]);
		c[1] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e[1], e[6]), _mm256_xor_si256(e[11], e[16])), e[21]);
		c[2] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e[2], e[7]), _mm256_xor_si256(e[12], e[17])), e[22]);
		c[3] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e[3], e[8]), _mm256_xor_si256(e[13], e[18])), e[23]);
		c[4] = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e[4], e[9]), _mm256_xor_si256(e[14], e[19])), e[24]);
		d[0] = _mm256_xor_si256(c[4], _mm256_or_si256(_mm256_slli_epi64(c[1], 1), _mm256_srli_epi64(c[1], 64 - 1)));
		d[1] = _mm256_xor_si256(c[0], _mm256_or_si256(_mm256_slli_epi64(c[2], 1), _mm256_srli_epi64(c[2], 64 - 1)));
		d[2] = _mm256_xor_si256(c[1], _mm256_or_si256(_mm256_slli_epi64(c[3], 1), _mm256_srli_epi64(c[3], 64 - 1)));
		d[3] = _mm256_xor_si256(c[2], _mm256_or_si256(_mm256_slli_epi64(c[4], 1), _mm256_srli_epi64(c[4], 64 - 1)));
		d[4] = _mm256_xor_si256(c[3], _mm256_or_si256(_mm256_slli_epi64(c[0], 1), _mm256_srli_epi64(c[0], 64 - 1)));
		e[0] = _mm256_xor_si256(e[0], d[0]);
		c[0] = e[0];
		e[6] = _mm256_xor_si256(e[6], d[1]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(e[6], 44), _mm256_srli_epi64(e[6], 64 - 44));
		e[12] = _mm256_xor_si256(e[12], d[2]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(e[12], 43), _mm256_srli_epi64(e[12], 64 - 43));
		e[18] = _mm256_xor_si256(e[18], d[3]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(e[18], 21), _mm256_srli_epi64(e[18], 64 - 21));
		e[24] = _mm256_xor_si256(e[24], d[4]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(e[24], 14), _mm256_srli_epi64(e[24], 64 - 14));
		a[0] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		a[0] = _mm256_xor_si256(a[0], _mm256_set1_epi64x(KECCAK_RC24[i + 1]));
		a[1] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		a[2] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		a[3] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		a[4] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		e[3] = _mm256_xor_si256(e[3], d[3]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(e[3], 28), _mm256_srli_epi64(e[3], 64 - 28));
		e[9] = _mm256_xor_si256(e[9], d[4]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(e[9], 20), _mm256_srli_epi64(e[9], 64 - 20));
		e[10] = _mm256_xor_si256(e[10], d[0]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(e[10], 3), _mm256_srli_epi64(e[10], 64 - 3));
		e[16] = _mm256_xor_si256(e[16], d[1]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(e[16], 45), _mm256_srli_epi64(e[16], 64 - 45));
		e[22] = _mm256_xor_si256(e[22], d[2]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(e[22], 61), _mm256_srli_epi64(e[22], 64 - 61));
		a[5] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		a[6] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		a[7] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		a[8] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		a[9] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		e[1] = _mm256_xor_si256(e[1], d[1]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(e[1], 1), _mm256_srli_epi64(e[1], 64 - 1));
		e[7] = _mm256_xor_si256(e[7], d[2]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(e[7], 6), _mm256_srli_epi64(e[7], 64 - 6));
		e[13] = _mm256_xor_si256(e[13], d[3]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(e[13], 25), _mm256_srli_epi64(e[13], 64 - 25));
		e[19] = _mm256_xor_si256(e[19], d[4]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(e[19], 8), _mm256_srli_epi64(e[19], 64 - 8));
		e[20] = _mm256_xor_si256(e[20], d[0]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(e[20], 18), _mm256_srli_epi64(e[20], 64 - 18));
		a[10] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		a[11] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		a[12] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		a[13] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		a[14] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		e[4] = _mm256_xor_si256(e[4], d[4]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(e[4], 27), _mm256_srli_epi64(e[4], 64 - 27));
		e[5] = _mm256_xor_si256(e[5], d[0]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(e[5], 36), _mm256_srli_epi64(e[5], 64 - 36));
		e[11] = _mm256_xor_si256(e[11], d[1]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(e[11], 10), _mm256_srli_epi64(e[11], 64 - 10));
		e[17] = _mm256_xor_si256(e[17], d[2]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(e[17], 15), _mm256_srli_epi64(e[17], 64 - 15));
		e[23] = _mm256_xor_si256(e[23], d[3]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(e[23], 56), _mm256_srli_epi64(e[23], 64 - 56));
		a[15] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		a[16] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		a[17] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		a[18] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		a[19] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
		e[2] = _mm256_xor_si256(e[2], d[2]);
		c[0] = _mm256_or_si256(_mm256_slli_epi64(e[2], 62), _mm256_srli_epi64(e[2], 64 - 62));
		e[8] = _mm256_xor_si256(e[8], d[3]);
		c[1] = _mm256_or_si256(_mm256_slli_epi64(e[8], 55), _mm256_srli_epi64(e[8], 64 - 55));
		e[14] = _mm256_xor_si256(e[14], d[4]);
		c[2] = _mm256_or_si256(_mm256_slli_epi64(e[14], 39), _mm256_srli_epi64(e[14], 64 - 39));
		e[15] = _mm256_xor_si256(e[15], d[0]);
		c[3] = _mm256_or_si256(_mm256_slli_epi64(e[15], 41), _mm256_srli_epi64(e[15], 64 - 41));
		e[21] = _mm256_xor_si256(e[21], d[1]);
		c[4] = _mm256_or_si256(_mm256_slli_epi64(e[21], 2), _mm256_srli_epi64(e[21], 64 - 2));
		a[20] = _mm256_xor_si256(c[0], _mm256_and_si256(_mm256_xor_si256(c[1], _mm256_set1_epi64x(-1)), c[2]));
		a[21] = _mm256_xor_si256(c[1], _mm256_and_si256(_mm256_xor_si256(c[2], _mm256_set1_epi64x(-1)), c[3]));
		a[22] = _mm256_xor_si256(c[2], _mm256_and_si256(_mm256_xor_si256(c[3], _mm256_set1_epi64x(-1)), c[4]));
		a[23] = _mm256_xor_si256(c[3], _mm256_and_si256(_mm256_xor_si256(c[4], _mm256_set1_epi64x(-1)), c[0]));
		a[24] = _mm256_xor_si256(c[4], _mm256_and_si256(_mm256_xor_si256(c[0], _mm256_set1_epi64x(-1)), c[1]));
	}

	for (i = 0; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		state[i] = a[i];
	}
}
#endif

/* common */

void qsc_keccak_permute(uint64_t* state)
{
#if defined(QSC_KECCAK_UNROLLED_PERMUTATION)
	qsc_keccak_permute_p1600(ctx->state)
#else
	qsc_keccak_permute_p1600(state, KECCAK_PERMUTATION_ROUNDS);
#endif
}

QSC_SYSTEM_OPTIMIZE_IGNORE
void qsc_keccak_dispose(qsc_keccak_state* ctx)
{
	if (ctx != NULL)
	{
		qsc_memutils_clear((uint8_t*)ctx->state, sizeof(ctx->state));
		qsc_memutils_clear(ctx->buffer, sizeof(ctx->buffer));
		ctx->position = 0;
	}
}
QSC_SYSTEM_OPTIMIZE_RESUME

/* sha3 */

void qsc_sha3_compute256(uint8_t* output, const uint8_t* message, size_t msglen)
{
	assert(output != NULL);
	assert(message != NULL);

	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_256_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	keccak_absorb(ctx.state, keccak_rate_256, message, msglen, KECCAK_SHA3_DOMAIN_ID);
	keccak_squeezeblocks(ctx.state, hash, 1, keccak_rate_256);
	qsc_memutils_copy(output, hash, QSC_SHA3_256_HASH_SIZE);
	qsc_keccak_dispose(&ctx);
}

void qsc_sha3_compute512(uint8_t* output, const uint8_t* message, size_t msglen)
{
	assert(output != NULL);
	assert(message != NULL);

	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_512_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	keccak_absorb(ctx.state, keccak_rate_512, message, msglen, KECCAK_SHA3_DOMAIN_ID);
	keccak_squeezeblocks(ctx.state, hash, 1, keccak_rate_512);
	qsc_memutils_copy(output, hash, QSC_SHA3_512_HASH_SIZE);
	qsc_keccak_dispose(&ctx);
}

void qsc_sha3_finalize(qsc_keccak_state* ctx, keccak_rate rate, uint8_t* output)
{
	assert(ctx != NULL);
	assert(output != NULL);

	size_t hlen;

	hlen = (((QSC_KECCAK_STATE_SIZE * sizeof(uint64_t)) - rate) / 2);
	qsc_memutils_clear((uint8_t*)(ctx->buffer + ctx->position), sizeof(ctx->buffer) - ctx->position);
	ctx->buffer[ctx->position] = KECCAK_SHA3_DOMAIN_ID;
	ctx->buffer[rate - 1] |= 128U;
	keccak_fast_absorb(ctx->state, ctx->buffer, rate);
	qsc_keccak_permute(ctx->state);

#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_copy(output, (uint8_t*)ctx->state, hlen);
#else

	for (size_t i = 0; i < hlen / sizeof(uint64_t); ++i)
	{
		qsc_intutils_le64to8(output, ctx->state[i]);
		output += sizeof(uint64_t);
	}
#endif

	qsc_keccak_dispose(ctx);
}

void qsc_sha3_initialize(qsc_keccak_state* ctx)
{
	qsc_keccak_dispose(ctx);
}

void qsc_sha3_update(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen)
{
	keccak_update(ctx, rate, message, msglen);
}

/* shake */

void qsc_shake128_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_128_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_128_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	qsc_shake_initialize(&ctx, keccak_rate_128, key, keylen);
	qsc_shake_squeezeblocks(&ctx, keccak_rate_128, output, nblocks);
	output += (nblocks * QSC_KECCAK_128_RATE);
	outlen -= (nblocks * QSC_KECCAK_128_RATE);

	if (outlen != 0)
	{
		qsc_shake_squeezeblocks(&ctx, keccak_rate_128, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(&ctx);
}

void qsc_shake256_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_256_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_256_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	qsc_shake_initialize(&ctx, keccak_rate_256, key, keylen);
	qsc_shake_squeezeblocks(&ctx, keccak_rate_256, output, nblocks);
	output += (nblocks * QSC_KECCAK_256_RATE);
	outlen -= (nblocks * QSC_KECCAK_256_RATE);

	if (outlen != 0)
	{
		qsc_shake_squeezeblocks(&ctx, keccak_rate_256, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(&ctx);
}

void qsc_shake512_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_512_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_512_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	qsc_shake_initialize(&ctx, keccak_rate_512, key, keylen);
	qsc_shake_squeezeblocks(&ctx, keccak_rate_512, output, nblocks);
	output += (nblocks * QSC_KECCAK_512_RATE);
	outlen -= (nblocks * QSC_KECCAK_512_RATE);

	if (outlen != 0)
	{
		qsc_shake_squeezeblocks(&ctx, keccak_rate_512, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(&ctx);
}

void qsc_shake_initialize(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	keccak_absorb(ctx->state, rate, key, keylen, KECCAK_SHAKE_DOMAIN_ID);
}

void qsc_shake_squeezeblocks(qsc_keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t nblocks)
{
	assert(ctx != NULL);
	assert(output != NULL);

	keccak_squeezeblocks(ctx->state, output, nblocks, rate);
}

/* cshake */

void qsc_cshake128_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_128_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_128_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));

	if (custlen + namelen != 0)
	{
		qsc_cshake_initialize(&ctx, keccak_rate_128, key, keylen, name, namelen, custom, custlen);
	}
	else
	{
		qsc_shake_initialize(&ctx, keccak_rate_128, key, keylen);
	}

	qsc_cshake_squeezeblocks(&ctx, keccak_rate_128, output, nblocks);
	output += (nblocks * QSC_KECCAK_128_RATE);
	outlen -= (nblocks * QSC_KECCAK_128_RATE);

	if (outlen != 0)
	{
		qsc_cshake_squeezeblocks(&ctx, keccak_rate_128, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(&ctx);
}

void qsc_cshake256_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_256_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_256_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));

	if (custlen + namelen != 0)
	{
		qsc_cshake_initialize(&ctx, keccak_rate_256, key, keylen, name, namelen, custom, custlen);
	}
	else
	{
		qsc_shake_initialize(&ctx, keccak_rate_256, key, keylen);
	}

	qsc_cshake_squeezeblocks(&ctx, keccak_rate_256, output, nblocks);

	output += (nblocks * QSC_KECCAK_256_RATE);
	outlen -= (nblocks * QSC_KECCAK_256_RATE);

	if (outlen != 0)
	{
		qsc_cshake_squeezeblocks(&ctx, keccak_rate_256, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(&ctx);
}

void qsc_cshake512_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_512_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_512_RATE] = { 0 };

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));

	if (custlen + namelen != 0)
	{
		qsc_cshake_initialize(&ctx, keccak_rate_512, key, keylen, name, namelen, custom, custlen);
	}
	else
	{
		qsc_shake_initialize(&ctx, keccak_rate_512, key, keylen);
	}

	qsc_cshake_squeezeblocks(&ctx, keccak_rate_512, output, nblocks);
	output += (nblocks * QSC_KECCAK_512_RATE);
	outlen -= (nblocks * QSC_KECCAK_512_RATE);

	if (outlen != 0)
	{
		qsc_cshake_squeezeblocks(&ctx, keccak_rate_512, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(&ctx);
}

void qsc_cshake_initialize(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	uint8_t pad[KECCAK_STATE_BYTE_SIZE] = { 0 };
	size_t i;
	size_t oft;

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode((uint8_t*)(pad + oft), namelen * 8);

	if (namelen != 0)
	{
		for (i = 0; i < namelen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				qsc_keccak_permute(ctx->state);
				oft = 0;
			}

			pad[oft] = name[i];
			++oft;
		}
	}

	oft += keccak_left_encode((uint8_t*)(pad + oft), custlen * 8);

	if (custlen != 0)
	{
		for (i = 0; i < custlen; ++i)
		{
			if (oft == rate)
			{
				keccak_fast_absorb(ctx->state, pad, rate);
				qsc_keccak_permute(ctx->state);
				oft = 0;
			}

			pad[oft] = custom[i];
			++oft;
		}
	}

	qsc_memutils_clear((uint8_t*)(pad + oft), rate - oft);
	keccak_fast_absorb(ctx->state, pad, rate);
	qsc_keccak_permute(ctx->state);

	/* initialize the key */
	keccak_absorb(ctx->state, rate, key, keylen, KECCAK_CSHAKE_DOMAIN_ID);
}

void qsc_cshake_squeezeblocks(qsc_keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t nblocks)
{
	assert(ctx != NULL);
	assert(output != NULL);

	keccak_squeezeblocks(ctx->state, output, nblocks, (size_t)rate);
}

void qsc_cshake_update(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen)
{
	while (keylen >= (size_t)rate)
	{
		keccak_fast_absorb(ctx->state, key, keylen);
		qsc_keccak_permute(ctx->state);
		keylen -= rate;
		key += rate;
	}

	if (keylen != 0)
	{
		keccak_fast_absorb(ctx->state, key, keylen);
		qsc_keccak_permute(ctx->state);
	}
}

/* kmac */

void qsc_kmac128_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	qsc_keccak_state ctx;

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	qsc_kmac_initialize(&ctx, keccak_rate_128, key, keylen, custom, custlen);
	qsc_kmac_update(&ctx, keccak_rate_128, message, msglen);
	qsc_kmac_finalize(&ctx, keccak_rate_128, output, outlen);
}

void qsc_kmac256_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	qsc_keccak_state ctx;

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	qsc_kmac_initialize(&ctx, keccak_rate_256, key, keylen, custom, custlen);
	qsc_kmac_update(&ctx, keccak_rate_256, message, msglen);
	qsc_kmac_finalize(&ctx, keccak_rate_256, output, outlen);
}

void qsc_kmac512_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(output != NULL);
	assert(message != NULL);
	assert(key != NULL);

	qsc_keccak_state ctx;

	qsc_memutils_clear((uint8_t*)ctx.state, sizeof(ctx.state));
	qsc_kmac_initialize(&ctx, keccak_rate_512, key, keylen, custom, custlen);
	qsc_kmac_update(&ctx, keccak_rate_512, message, msglen);
	qsc_kmac_finalize(&ctx, keccak_rate_512, output, outlen);
}

void qsc_kmac_finalize(qsc_keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t outlen)
{
	uint8_t buf[sizeof(size_t) + 1] = { 0 };
	uint8_t pad[KECCAK_STATE_BYTE_SIZE] = { 0 };
	size_t bitlen;

	qsc_memutils_copy(pad, ctx->buffer, ctx->position);
	bitlen = keccak_right_encode(buf, outlen * 8);
	qsc_memutils_copy((uint8_t*)(pad + ctx->position), buf, bitlen);

	pad[ctx->position + bitlen] = KECCAK_KMAC_DOMAIN_ID;
	pad[rate - 1] |= 128U;
	keccak_fast_absorb(ctx->state, pad, rate);

	while (outlen >= (size_t)rate)
	{
		keccak_squeezeblocks(ctx->state, pad, 1, rate);
		qsc_memutils_copy(output, pad, rate);
		output += rate;
		outlen -= rate;
	}

	if (outlen > 0)
	{
		keccak_squeezeblocks(ctx->state, pad, 1, rate);
		qsc_memutils_copy(output, pad, outlen);
	}

	qsc_memutils_clear(ctx->buffer, sizeof(ctx->buffer));
	ctx->position = 0;
}

void qsc_kmac_initialize(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	uint8_t pad[QSC_KECCAK_STATE_SIZE * sizeof(uint64_t)] = { 0 };
	const uint8_t name[] = { 0x4B, 0x4D, 0x41, 0x43 };
	size_t oft;
	size_t i;

	qsc_memutils_clear((uint8_t*)ctx->state, sizeof(ctx->state));
	qsc_memutils_clear(ctx->buffer, sizeof(ctx->buffer));
	ctx->position = 0;

	/* stage 1: name + custom */

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode((uint8_t*)(pad + oft), sizeof(name) * 8);

	for (i = 0; i < sizeof(name); ++i)
	{
		pad[oft + i] = name[i];
	}

	oft += sizeof(name);
	oft += keccak_left_encode((uint8_t*)(pad + oft), custlen * 8);

	for (i = 0; i < custlen; ++i)
	{
		if (oft == rate)
		{
			keccak_fast_absorb(ctx->state, pad, rate);
			qsc_keccak_permute(ctx->state);
			oft = 0;
		}

		pad[oft] = custom[i];
		++oft;
	}

	qsc_memutils_clear((uint8_t*)(pad + oft), rate - oft);
	keccak_fast_absorb(ctx->state, pad, rate);
	qsc_keccak_permute(ctx->state);

	/* stage 2: key */

	qsc_memutils_clear(pad, rate);
	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode((uint8_t*)(pad + oft), keylen * 8);

	for (i = 0; i < keylen; ++i)
	{
		if (oft == rate)
		{
			keccak_fast_absorb(ctx->state, pad, rate);
			qsc_keccak_permute(ctx->state);
			oft = 0;
		}

		pad[oft] = key[i];
		++oft;
	}

	qsc_memutils_clear((uint8_t*)(pad + oft), rate - oft);
	keccak_fast_absorb(ctx->state, pad, rate);
	qsc_keccak_permute(ctx->state);
}

void qsc_kmac_update(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen)
{
	keccak_update(ctx, rate, message, msglen);
}

/* kpa - Keccak-based Parallel Authentication */

static kpa_fast_absorb(qsc_kpa_state* ctx, const uint8_t* message)
{
	size_t i;

	for (i = 0; i < QSC_KPA_PARALLELISM; ++i)
	{
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		qsc_memutils_xor((uint8_t*)ctx->state[i], (uint8_t*)(message + (i * (size_t)ctx->rate)), (size_t)ctx->rate);
#else
		for (size_t j = 0; j < (size_t)ctx->rate / sizeof(uint64_t); ++j)
		{
			ctx->state[i][j] ^= qsc_intutils_le8to64((uint8_t*)(message + (i * (size_t)ctx->rate) + (j * sizeof(uint64_t))));
		}
#endif
	}
}

static kpa_permute(qsc_kpa_state* ctx)
{
	size_t i;

	for (i = 0; i < QSC_KPA_PARALLELISM; ++i)
	{
		qsc_keccak_permute_p1600(ctx->state[i], QSC_KPA_ROUNDS);
	}

	ctx->processed += (size_t)ctx->rate * QSC_KPA_PARALLELISM;
}

static void kpa_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks, keccak_rate rate)
{
	while (nblocks > 0)
	{
		qsc_keccak_permute_p1600(state, QSC_KPA_ROUNDS);

#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		qsc_memutils_copy(output, (uint8_t*)state, (size_t)rate);
#else
		for (size_t i = 0; i < (rate >> 3); ++i)
		{
			qsc_intutils_le64to8((uint8_t*)(output + sizeof(uint64_t) * i), state[i]);
		}
#endif
		output += rate;
		nblocks--;
	}
}

#if defined(QSC_KPA_AVX_PARALLEL)

static kpa_permutew(qsc_kpa_state* ctx)
{
#if defined(QSC_SYSTEM_HAS_AVX512)
	qsc_keccak_permute_p8x1600(ctx->statew, QSC_KPA_ROUNDS);
#elif defined(QSC_SYSTEM_HAS_AVX2)
	qsc_keccak_permute_p4x1600(ctx->statew[0], QSC_KPA_ROUNDS);
	qsc_keccak_permute_p4x1600(ctx->statew[1], QSC_KPA_ROUNDS);
#endif

	ctx->processed += (size_t)ctx->rate * QSC_KPA_PARALLELISM;
}

static kpa_fast_absorbw(qsc_kpa_state* ctx, const uint8_t* message)
{
	size_t i;

#if defined(QSC_SYSTEM_HAS_AVX512)

	const size_t ROFT = (size_t)ctx->rate;
	uint64_t tmp[8] = { 0 };
	__m512i wbuf;
	const uint8_t* pmsg = message;

	for (i = 0; i < (size_t)ctx->rate / sizeof(uint64_t); ++i)
	{
		tmp[0] = qsc_intutils_le8to64((uint8_t*)pmsg);
		tmp[1] = qsc_intutils_le8to64((uint8_t*)(pmsg + ROFT));
		tmp[2] = qsc_intutils_le8to64((uint8_t*)(pmsg + (2 * ROFT)));
		tmp[3] = qsc_intutils_le8to64((uint8_t*)(pmsg + (3 * ROFT)));
		tmp[4] = qsc_intutils_le8to64((uint8_t*)(pmsg + (4 * ROFT)));
		tmp[5] = qsc_intutils_le8to64((uint8_t*)(pmsg + (5 * ROFT)));
		tmp[6] = qsc_intutils_le8to64((uint8_t*)(pmsg + (6 * ROFT)));
		tmp[7] = qsc_intutils_le8to64((uint8_t*)(pmsg + (7 * ROFT)));

		wbuf = _mm512_loadu_si512((const __m512i*)tmp);
		ctx->statew[i] = _mm512_xor_si512(ctx->statew[i], wbuf);
		pmsg += sizeof(uint64_t);
	}

#elif defined(QSC_SYSTEM_HAS_AVX2)

	const size_t ROFT = (size_t)ctx->rate;
	uint64_t tmp[4] = { 0 };
	__m256i wbuf;
	const uint8_t* pmsg = message;

	for (i = 0; i < (size_t)ctx->rate / sizeof(uint64_t); ++i)
	{
		tmp[0] = qsc_intutils_le8to64((uint8_t*)pmsg);
		tmp[1] = qsc_intutils_le8to64((uint8_t*)(pmsg + ROFT));
		tmp[2] = qsc_intutils_le8to64((uint8_t*)(pmsg + (2 * ROFT)));
		tmp[3] = qsc_intutils_le8to64((uint8_t*)(pmsg + (3 * ROFT)));
		wbuf = _mm256_loadu_si256((const __m256i*)tmp);
		ctx->statew[0][i] = _mm256_xor_si256(ctx->statew[0][i], wbuf);

		tmp[0] = qsc_intutils_le8to64((uint8_t*)(pmsg + (4 * ROFT)));
		tmp[1] = qsc_intutils_le8to64((uint8_t*)(pmsg + (5 * ROFT)));
		tmp[2] = qsc_intutils_le8to64((uint8_t*)(pmsg + (6 * ROFT)));
		tmp[3] = qsc_intutils_le8to64((uint8_t*)(pmsg + (7 * ROFT)));
		wbuf = _mm256_loadu_si256((const __m256i*)tmp);
		ctx->statew[1][i] = _mm256_xor_si256(ctx->statew[1][i], wbuf);

		pmsg += sizeof(uint64_t);
	}

#endif
}

static void kpa_load_state(qsc_kpa_state* ctx)
{
	size_t i;

#if defined(QSC_SYSTEM_HAS_AVX512)

	uint64_t tmp[8] = { 0 };

	for (i = 0; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		tmp[0] = ctx->state[0][i];
		tmp[1] = ctx->state[1][i];
		tmp[2] = ctx->state[2][i];
		tmp[3] = ctx->state[3][i];
		tmp[4] = ctx->state[4][i];
		tmp[5] = ctx->state[5][i];
		tmp[6] = ctx->state[6][i];
		tmp[7] = ctx->state[7][i];

		ctx->statew[i] = _mm512_loadu_si512((const __m512i*)tmp);
	}

#elif defined(QSC_SYSTEM_HAS_AVX2)

	uint64_t tmp[4] = { 0 };

	for (i = 0; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		tmp[0] = ctx->state[0][i];
		tmp[1] = ctx->state[1][i];
		tmp[2] = ctx->state[2][i];
		tmp[3] = ctx->state[3][i];
		ctx->statew[0][i] = _mm256_loadu_si256((const __m256i*)tmp);
		tmp[0] = ctx->state[4][i];
		tmp[1] = ctx->state[5][i];
		tmp[2] = ctx->state[6][i];
		tmp[3] = ctx->state[7][i];
		ctx->statew[1][i] = _mm256_loadu_si256((const __m256i*)tmp);
	}
#endif
}

static void kpa_store_state(qsc_kpa_state* ctx)
{
	size_t i;

#if defined(QSC_SYSTEM_HAS_AVX512)

	uint64_t tmp[8] = { 0 };

	for (i = 0; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		_mm512_storeu_si512((__m512i*)tmp, ctx->statew[i]);
		ctx->state[0][i] = tmp[0];
		ctx->state[1][i] = tmp[1];
		ctx->state[2][i] = tmp[2];
		ctx->state[3][i] = tmp[3];
		ctx->state[4][i] = tmp[4];
		ctx->state[5][i] = tmp[5];
		ctx->state[6][i] = tmp[6];
		ctx->state[7][i] = tmp[7];
	}

#elif defined(QSC_SYSTEM_HAS_AVX2)

	uint64_t tmp[4] = { 0 };

	for (i = 0; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		_mm256_storeu_si256((__m256i*)tmp, ctx->statew[0][i]);
		ctx->state[0][i] = tmp[0];
		ctx->state[1][i] = tmp[1];
		ctx->state[2][i] = tmp[2];
		ctx->state[3][i] = tmp[3];
		_mm256_storeu_si256((__m256i*)tmp, ctx->statew[1][i]);
		ctx->state[4][i] = tmp[0];
		ctx->state[5][i] = tmp[1];
		ctx->state[6][i] = tmp[2];
		ctx->state[7][i] = tmp[3];
	}

#endif
}
#endif

void qsc_kpa_finalize(qsc_kpa_state* ctx, uint8_t* output, size_t outlen)
{
	uint64_t pstate[QSC_KECCAK_STATE_SIZE] = { 0 };
	uint8_t prcb[2 * sizeof(uint64_t)] = { 0 };
	size_t bitlen;
	size_t i;

	/* clear unused buffer */
	if (ctx->position != 0)
	{
		qsc_memutils_clear(ctx->buffer + ctx->position, sizeof(ctx->buffer) - ctx->position);
#if defined(QSC_KPA_AVX_PARALLEL)
		kpa_fast_absorbw(ctx, ctx->buffer);
		kpa_permutew(ctx);
#else
		/* absorb the buffer into the leaf states */
		kpa_fast_absorb(ctx, ctx->buffer);
		/* permute the leaf states */
		kpa_permute(ctx);
#endif
	}

	/* set processed the counter to final position */
	ctx->processed += ctx->position;

#if defined(QSC_KPA_AVX_PARALLEL)
		kpa_store_state(ctx);
#endif

	/* absorb and permute leaf node states into the parent state  */
	for (i = 0; i < QSC_KPA_PARALLELISM; ++i)
	{
		/* copy each of the leaf states to the buffer */
		qsc_memutils_copy((uint8_t*)(ctx->buffer + (i * (size_t)ctx->rate)), (uint8_t*)ctx->state[i], (size_t)ctx->rate);
		/* absorb each leaf into the parent state */
		keccak_fast_absorb(pstate, (uint8_t*)(ctx->buffer + (i * (size_t)ctx->rate)), (size_t)ctx->rate);
		/* permute the parent state */
		qsc_keccak_permute_p1600(pstate, QSC_KPA_ROUNDS);
	}

	/* clear buffer and process final block */
	qsc_memutils_clear(ctx->buffer, sizeof(ctx->buffer));
	/* add total processed bytes and output length to padding string */
	bitlen = keccak_right_encode(prcb, outlen * 8);
	bitlen += keccak_right_encode(prcb + bitlen, ctx->processed * 8);
	/* copy to buffer */
	qsc_memutils_copy((uint8_t*)(ctx->buffer), prcb, bitlen);
	/* add the domain id */
	ctx->buffer[bitlen] = KECCAK_KPA_DOMAIN_ID;
	/* clamp the last byte */
	ctx->buffer[(size_t)ctx->rate - 1] |= 128U;
	/* absorb the buffer into parent state */
	keccak_fast_absorb(pstate, ctx->buffer, ctx->rate);

	/* squeeze blocks to produce the output hash */
	while (outlen >= (size_t)ctx->rate)
	{
		keccak_squeezeblocks(pstate, ctx->buffer, 1, ctx->rate);
		qsc_memutils_copy(output, ctx->buffer, ctx->rate);
		output += ctx->rate;
		outlen -= ctx->rate;
	}

	/* add unaligned hash bytes */
	if (outlen > 0)
	{
		keccak_squeezeblocks(pstate, ctx->buffer, 1, ctx->rate);
		qsc_memutils_copy(output, ctx->buffer, outlen);
	}

	/* reset the buffer and counters */
	qsc_memutils_clear(ctx->buffer, sizeof(ctx->buffer));
	ctx->position = 0;
	ctx->processed = 0;
}

void qsc_kpa_initialize(qsc_kpa_state* ctx, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	assert(ctx != NULL);
	assert(key != NULL);

	uint64_t tmps[QSC_KECCAK_STATE_SIZE * QSC_KPA_PARALLELISM] = { 0 };
	uint8_t pad[QSC_KECCAK_STATE_BYTE_SIZE] = { 0 };
	const uint8_t algb[] = { 0x4B, 0x42, 0x41, 0xAD, 0x31, 0x32, 0x00, 0x00 };
	uint64_t algn;
	size_t oft;
	size_t i;

	/* set state values */
	ctx->position = 0;
	ctx->processed = 0;
	ctx->rate = (keylen == QSC_KPA_256_KEY_SIZE) ? QSC_KECCAK_256_RATE : QSC_KECCAK_512_RATE;
	qsc_memutils_clear((uint8_t*)ctx->state, sizeof(ctx->state));
	qsc_memutils_clear(ctx->buffer, sizeof(ctx->buffer));

	/* stage 1: construct name string, rate + name-size-bits + formal name */

	oft = keccak_left_encode(pad, ctx->rate);
	oft += keccak_left_encode((uint8_t*)(pad + oft), sizeof(algb) * 8);

	for (i = 0; i < sizeof(algb); ++i)
	{
		pad[oft + i] = algb[i];
	}

	/* stage 2: add name + custom to state */

	oft += sizeof(algb);
	oft += keccak_left_encode((uint8_t*)(pad + oft), custlen * 8);

	for (i = 0; i < custlen; ++i)
	{
		if (oft == (size_t)ctx->rate)
		{
			keccak_fast_absorb(tmps, pad, ctx->rate);
			qsc_keccak_permute_p1600(tmps, QSC_KPA_ROUNDS);
			oft = 0;
		}

		pad[oft] = custom[i];
		++oft;
	}

	/* absorb custom and name, and permute state */
	qsc_memutils_clear((uint8_t*)(pad + oft), (size_t)ctx->rate - oft);
	keccak_fast_absorb(tmps, pad, ctx->rate);
	qsc_keccak_permute_p1600(tmps, QSC_KPA_ROUNDS);

	/* stage 3: add key to state  */

	qsc_memutils_clear(pad, ctx->rate);
	oft = keccak_left_encode(pad, ctx->rate);
	oft += keccak_left_encode((uint8_t*)(pad + oft), keylen * 8);

	for (i = 0; i < keylen; ++i)
	{
		if (oft == (size_t)ctx->rate)
		{
			keccak_fast_absorb(tmps, pad, ctx->rate);
			qsc_keccak_permute_p1600(tmps, QSC_KPA_ROUNDS);
			oft = 0;
		}

		pad[oft] = key[i];
		++oft;
	}

	/* absorb the key and permute the state */
	qsc_memutils_clear((uint8_t*)(pad + oft), ctx->rate - oft);
	keccak_fast_absorb(tmps, pad, ctx->rate);
	qsc_keccak_permute_p1600(tmps, QSC_KPA_ROUNDS);

	/* copy state to leaf node states */
	for (i = 0; i < QSC_KPA_PARALLELISM; ++i)
	{
		/* store the state index to the algorithm name */
		qsc_intutils_be16to8((uint8_t*)(algb + 6), (uint16_t)(i + 1));
		/* copy the name to a 64-bit integer */
		algn = qsc_intutils_be8to64(algb);
		/* copy the parent state to a leaf node */
		qsc_memutils_copy((uint8_t*)ctx->state[i], (uint8_t*)tmps, QSC_KECCAK_STATE_BYTE_SIZE);
		/* absorb the leafs unique index name */
		ctx->state[i][0] ^= algn;
	}

#if defined(QSC_KPA_AVX_PARALLEL)
	kpa_load_state(ctx);
#endif
}

void qsc_kpa_update(qsc_kpa_state* ctx, const uint8_t* message, size_t msglen)
{
	// add message to buffer
	// if buffer full or exceeds buffer size..
	// permute all blocks
	// else fill buffer by absorbing linearly
	assert(ctx != NULL);
	assert(message != NULL);

	const size_t BLKLEN = (size_t)ctx->rate * QSC_KPA_PARALLELISM;

	if (msglen != 0)
	{
		if (ctx->position != 0 && (ctx->position + msglen >= BLKLEN))
		{
			const size_t RMDLEN = BLKLEN - ctx->position;

			if (RMDLEN != 0)
			{
				qsc_memutils_copy((uint8_t*)(ctx->buffer + ctx->position), message, RMDLEN);
			}

#if defined(QSC_KPA_AVX_PARALLEL)
			kpa_fast_absorbw(ctx, ctx->buffer);
			kpa_permutew(ctx);
#else
			kpa_fast_absorb(ctx, ctx->buffer);
			kpa_permute(ctx);
#endif

			ctx->position = 0;
			message += RMDLEN;
			msglen -= RMDLEN;
		}

		/* sequential loop through blocks */
		while (msglen >= BLKLEN)
		{
#if defined(QSC_KPA_AVX_PARALLEL)
			kpa_fast_absorbw(ctx, message);
			kpa_permutew(ctx);
#else
			kpa_fast_absorb(ctx, message);
			kpa_permute(ctx);
#endif
			message += BLKLEN;
			msglen -= BLKLEN;
		}

		/* store unaligned bytes */
		if (msglen != 0)
		{
			qsc_memutils_copy((uint8_t*)(ctx->buffer + ctx->position), message, msglen);
			ctx->position += msglen;
		}
	}
}
