#include "sha3.h"
#include "intutils.h"

/*lint -e747 */

/* internal */

static size_t left_encode(uint8_t* buffer, size_t value)
{
	size_t i;
	size_t n;
	size_t v;

	/* jgu checked false warning */
	/*lint -save -e722 */
	for (v = value, n = 0; v != 0 && (n < sizeof(size_t)); ++n, v >>= 8) {};
	/*lint -restore */

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

static size_t right_encode(uint8_t* buffer, size_t value)
{
	size_t i;
	size_t n;
	size_t v;

	/* jgu checked false warning */
	/*lint -save -e722 */
	for (v = value, n = 0; v != 0 && (n < sizeof(size_t)); ++n, v >>= 8) {};
	/*lint -restore */

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

/* keccak */

static void keccak_absorb(uint64_t* state, size_t rate, const uint8_t* input, size_t inplen, uint8_t domain)
{
	uint8_t msg[SHA3_STATE_SIZE * sizeof(uint64_t)];
	size_t i;

	while (inplen >= rate)
	{
		for (i = 0; i < rate / sizeof(uint64_t); ++i)
		{
			state[i] ^= le8to64(input + (sizeof(uint64_t) * i));
		}

		keccak_permute(state);

		inplen -= rate;
		input += rate;
	}

	for (i = 0; i < inplen; ++i)
	{
		msg[i] = input[i];
	}

	msg[inplen] = domain;

	for (i = inplen + 1; i < rate; ++i)
	{
		msg[i] = 0;
	}

	msg[rate - 1] |= 128U;

	for (i = 0; i < rate / 8; ++i)
	{
		state[i] ^= le8to64(msg + (8 * i));
	}
}

static void keccak_squeezeblocks(uint64_t* state, uint8_t* output, size_t nblocks, size_t rate)
{
	size_t i;

	while (nblocks > 0)
	{
		keccak_permute(state);

		for (i = 0; i < (rate >> 3); ++i)
		{
			le64to8(output + sizeof(uint64_t) * i, state[i]);
		}

		output += rate;
		nblocks--;
	}
}

#ifdef KECCAK_COMPACT_PERMUTATION

/* keccak round constants */
static const uint64_t KeccakF_RoundConstants[KECCAK_PERMUTATION_ROUNDS] =
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

void keccak_permute(uint64_t* state)
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

	for (i = 0; i < KECCAK_PERMUTATION_ROUNDS; i += 2)
	{
		/* prepareTheta */
		BCa = Aba ^ Aga^Aka^Ama^Asa;
		BCe = Abe ^ Age^Ake^Ame^Ase;
		BCi = Abi ^ Agi^Aki^Ami^Asi;
		BCo = Abo ^ Ago^Ako^Amo^Aso;
		BCu = Abu ^ Agu^Aku^Amu^Asu;

		/* thetaRhoPiChiIotaPrepareTheta */
		Da = BCu ^ rotl64(BCe, 1);
		De = BCa ^ rotl64(BCi, 1);
		Di = BCe ^ rotl64(BCo, 1);
		Do = BCi ^ rotl64(BCu, 1);
		Du = BCo ^ rotl64(BCa, 1);

		Aba ^= Da;
		BCa = Aba;
		Age ^= De;
		BCe = rotl64(Age, 44);
		Aki ^= Di;
		BCi = rotl64(Aki, 43);
		Amo ^= Do;
		BCo = rotl64(Amo, 21);
		Asu ^= Du;
		BCu = rotl64(Asu, 14);
		Eba = BCa ^ ((~BCe)&  BCi);
		Eba ^= KeccakF_RoundConstants[i];
		Ebe = BCe ^ ((~BCi)&  BCo);
		Ebi = BCi ^ ((~BCo)&  BCu);
		Ebo = BCo ^ ((~BCu)&  BCa);
		Ebu = BCu ^ ((~BCa)&  BCe);

		Abo ^= Do;
		BCa = rotl64(Abo, 28);
		Agu ^= Du;
		BCe = rotl64(Agu, 20);
		Aka ^= Da;
		BCi = rotl64(Aka, 3);
		Ame ^= De;
		BCo = rotl64(Ame, 45);
		Asi ^= Di;
		BCu = rotl64(Asi, 61);
		Ega = BCa ^ ((~BCe)&  BCi);
		Ege = BCe ^ ((~BCi)&  BCo);
		Egi = BCi ^ ((~BCo)&  BCu);
		Ego = BCo ^ ((~BCu)&  BCa);
		Egu = BCu ^ ((~BCa)&  BCe);

		Abe ^= De;
		BCa = rotl64(Abe, 1);
		Agi ^= Di;
		BCe = rotl64(Agi, 6);
		Ako ^= Do;
		BCi = rotl64(Ako, 25);
		Amu ^= Du;
		BCo = rotl64(Amu, 8);
		Asa ^= Da;
		BCu = rotl64(Asa, 18);
		Eka = BCa ^ ((~BCe)&  BCi);
		Eke = BCe ^ ((~BCi)&  BCo);
		Eki = BCi ^ ((~BCo)&  BCu);
		Eko = BCo ^ ((~BCu)&  BCa);
		Eku = BCu ^ ((~BCa)&  BCe);

		Abu ^= Du;
		BCa = rotl64(Abu, 27);
		Aga ^= Da;
		BCe = rotl64(Aga, 36);
		Ake ^= De;
		BCi = rotl64(Ake, 10);
		Ami ^= Di;
		BCo = rotl64(Ami, 15);
		Aso ^= Do;
		BCu = rotl64(Aso, 56);
		Ema = BCa ^ ((~BCe)&  BCi);
		Eme = BCe ^ ((~BCi)&  BCo);
		Emi = BCi ^ ((~BCo)&  BCu);
		Emo = BCo ^ ((~BCu)&  BCa);
		Emu = BCu ^ ((~BCa)&  BCe);

		Abi ^= Di;
		BCa = rotl64(Abi, 62);
		Ago ^= Do;
		BCe = rotl64(Ago, 55);
		Aku ^= Du;
		BCi = rotl64(Aku, 39);
		Ama ^= Da;
		BCo = rotl64(Ama, 41);
		Ase ^= De;
		BCu = rotl64(Ase, 2);
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
		Da = BCu ^ rotl64(BCe, 1);
		De = BCa ^ rotl64(BCi, 1);
		Di = BCe ^ rotl64(BCo, 1);
		Do = BCi ^ rotl64(BCu, 1);
		Du = BCo ^ rotl64(BCa, 1);

		Eba ^= Da;
		BCa = Eba;
		Ege ^= De;
		BCe = rotl64(Ege, 44);
		Eki ^= Di;
		BCi = rotl64(Eki, 43);
		Emo ^= Do;
		BCo = rotl64(Emo, 21);
		Esu ^= Du;
		BCu = rotl64(Esu, 14);
		Aba = BCa ^ ((~BCe)&  BCi);
		Aba ^= KeccakF_RoundConstants[i + 1];
		Abe = BCe ^ ((~BCi)&  BCo);
		Abi = BCi ^ ((~BCo)&  BCu);
		Abo = BCo ^ ((~BCu)&  BCa);
		Abu = BCu ^ ((~BCa)&  BCe);

		Ebo ^= Do;
		BCa = rotl64(Ebo, 28);
		Egu ^= Du;
		BCe = rotl64(Egu, 20);
		Eka ^= Da;
		BCi = rotl64(Eka, 3);
		Eme ^= De;
		BCo = rotl64(Eme, 45);
		Esi ^= Di;
		BCu = rotl64(Esi, 61);
		Aga = BCa ^ ((~BCe)&  BCi);
		Age = BCe ^ ((~BCi)&  BCo);
		Agi = BCi ^ ((~BCo)&  BCu);
		Ago = BCo ^ ((~BCu)&  BCa);
		Agu = BCu ^ ((~BCa)&  BCe);

		Ebe ^= De;
		BCa = rotl64(Ebe, 1);
		Egi ^= Di;
		BCe = rotl64(Egi, 6);
		Eko ^= Do;
		BCi = rotl64(Eko, 25);
		Emu ^= Du;
		BCo = rotl64(Emu, 8);
		Esa ^= Da;
		BCu = rotl64(Esa, 18);
		Aka = BCa ^ ((~BCe)&  BCi);
		Ake = BCe ^ ((~BCi)&  BCo);
		Aki = BCi ^ ((~BCo)&  BCu);
		Ako = BCo ^ ((~BCu)&  BCa);
		Aku = BCu ^ ((~BCa)&  BCe);

		Ebu ^= Du;
		BCa = rotl64(Ebu, 27);
		Ega ^= Da;
		BCe = rotl64(Ega, 36);
		Eke ^= De;
		BCi = rotl64(Eke, 10);
		Emi ^= Di;
		BCo = rotl64(Emi, 15);
		Eso ^= Do;
		BCu = rotl64(Eso, 56);
		Ama = BCa ^ ((~BCe)&  BCi);
		Ame = BCe ^ ((~BCi)&  BCo);
		Ami = BCi ^ ((~BCo)&  BCu);
		Amo = BCo ^ ((~BCu)&  BCa);
		Amu = BCu ^ ((~BCa)&  BCe);

		Ebi ^= Di;
		BCa = rotl64(Ebi, 62);
		Ego ^= Do;
		BCe = rotl64(Ego, 55);
		Eku ^= Du;
		BCi = rotl64(Eku, 39);
		Ema ^= Da;
		BCo = rotl64(Ema, 41);
		Ese ^= De;
		BCu = rotl64(Ese, 2);
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

#else

void keccak_permute(uint64_t* state)
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000000000001ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000000008082ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x800000000000808AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000080008000ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000808BULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000080000001ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000080008081ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008009ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000008AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x0000000000000088ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000080008009ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x000000008000000AULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000008000808BULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x800000000000008BULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000000008089ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008003ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000000008002ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000000080ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x000000000000800AULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x800000008000000AULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x8000000080008081ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000000008080ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Aba ^= Da;
	Ca = Aba;
	Age ^= De;
	Ce = rotl64(Age, 44);
	Aki ^= Di;
	Ci = rotl64(Aki, 43);
	Amo ^= Do;
	Co = rotl64(Amo, 21);
	Asu ^= Du;
	Cu = rotl64(Asu, 14);
	Eba = Ca ^ ((~Ce) & Ci);
	Eba ^= 0x0000000080000001ULL;
	Ebe = Ce ^ ((~Ci) & Co);
	Ebi = Ci ^ ((~Co) & Cu);
	Ebo = Co ^ ((~Cu) & Ca);
	Ebu = Cu ^ ((~Ca) & Ce);
	Abo ^= Do;
	Ca = rotl64(Abo, 28);
	Agu ^= Du;
	Ce = rotl64(Agu, 20);
	Aka ^= Da;
	Ci = rotl64(Aka, 3);
	Ame ^= De;
	Co = rotl64(Ame, 45);
	Asi ^= Di;
	Cu = rotl64(Asi, 61);
	Ega = Ca ^ ((~Ce) & Ci);
	Ege = Ce ^ ((~Ci) & Co);
	Egi = Ci ^ ((~Co) & Cu);
	Ego = Co ^ ((~Cu) & Ca);
	Egu = Cu ^ ((~Ca) & Ce);
	Abe ^= De;
	Ca = rotl64(Abe, 1);
	Agi ^= Di;
	Ce = rotl64(Agi, 6);
	Ako ^= Do;
	Ci = rotl64(Ako, 25);
	Amu ^= Du;
	Co = rotl64(Amu, 8);
	Asa ^= Da;
	Cu = rotl64(Asa, 18);
	Eka = Ca ^ ((~Ce) & Ci);
	Eke = Ce ^ ((~Ci) & Co);
	Eki = Ci ^ ((~Co) & Cu);
	Eko = Co ^ ((~Cu) & Ca);
	Eku = Cu ^ ((~Ca) & Ce);
	Abu ^= Du;
	Ca = rotl64(Abu, 27);
	Aga ^= Da;
	Ce = rotl64(Aga, 36);
	Ake ^= De;
	Ci = rotl64(Ake, 10);
	Ami ^= Di;
	Co = rotl64(Ami, 15);
	Aso ^= Do;
	Cu = rotl64(Aso, 56);
	Ema = Ca ^ ((~Ce) & Ci);
	Eme = Ce ^ ((~Ci) & Co);
	Emi = Ci ^ ((~Co) & Cu);
	Emo = Co ^ ((~Cu) & Ca);
	Emu = Cu ^ ((~Ca) & Ce);
	Abi ^= Di;
	Ca = rotl64(Abi, 62);
	Ago ^= Do;
	Ce = rotl64(Ago, 55);
	Aku ^= Du;
	Ci = rotl64(Aku, 39);
	Ama ^= Da;
	Co = rotl64(Ama, 41);
	Ase ^= De;
	Cu = rotl64(Ase, 2);
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
	Da = Cu ^ rotl64(Ce, 1);
	De = Ca ^ rotl64(Ci, 1);
	Di = Ce ^ rotl64(Co, 1);
	Do = Ci ^ rotl64(Cu, 1);
	Du = Co ^ rotl64(Ca, 1);
	Eba ^= Da;
	Ca = Eba;
	Ege ^= De;
	Ce = rotl64(Ege, 44);
	Eki ^= Di;
	Ci = rotl64(Eki, 43);
	Emo ^= Do;
	Co = rotl64(Emo, 21);
	Esu ^= Du;
	Cu = rotl64(Esu, 14);
	Aba = Ca ^ ((~Ce) & Ci);
	Aba ^= 0x8000000080008008ULL;
	Abe = Ce ^ ((~Ci) & Co);
	Abi = Ci ^ ((~Co) & Cu);
	Abo = Co ^ ((~Cu) & Ca);
	Abu = Cu ^ ((~Ca) & Ce);
	Ebo ^= Do;
	Ca = rotl64(Ebo, 28);
	Egu ^= Du;
	Ce = rotl64(Egu, 20);
	Eka ^= Da;
	Ci = rotl64(Eka, 3);
	Eme ^= De;
	Co = rotl64(Eme, 45);
	Esi ^= Di;
	Cu = rotl64(Esi, 61);
	Aga = Ca ^ ((~Ce) & Ci);
	Age = Ce ^ ((~Ci) & Co);
	Agi = Ci ^ ((~Co) & Cu);
	Ago = Co ^ ((~Cu) & Ca);
	Agu = Cu ^ ((~Ca) & Ce);
	Ebe ^= De;
	Ca = rotl64(Ebe, 1);
	Egi ^= Di;
	Ce = rotl64(Egi, 6);
	Eko ^= Do;
	Ci = rotl64(Eko, 25);
	Emu ^= Du;
	Co = rotl64(Emu, 8);
	Esa ^= Da;
	Cu = rotl64(Esa, 18);
	Aka = Ca ^ ((~Ce) & Ci);
	Ake = Ce ^ ((~Ci) & Co);
	Aki = Ci ^ ((~Co) & Cu);
	Ako = Co ^ ((~Cu) & Ca);
	Aku = Cu ^ ((~Ca) & Ce);
	Ebu ^= Du;
	Ca = rotl64(Ebu, 27);
	Ega ^= Da;
	Ce = rotl64(Ega, 36);
	Eke ^= De;
	Ci = rotl64(Eke, 10);
	Emi ^= Di;
	Co = rotl64(Emi, 15);
	Eso ^= Do;
	Cu = rotl64(Eso, 56);
	Ama = Ca ^ ((~Ce) & Ci);
	Ame = Ce ^ ((~Ci) & Co);
	Ami = Ci ^ ((~Co) & Cu);
	Amo = Co ^ ((~Cu) & Ca);
	Amu = Cu ^ ((~Ca) & Ce);
	Ebi ^= Di;
	Ca = rotl64(Ebi, 62);
	Ego ^= Do;
	Ce = rotl64(Ego, 55);
	Eku ^= Du;
	Ci = rotl64(Eku, 39);
	Ema ^= Da;
	Co = rotl64(Ema, 41);
	Ese ^= De;
	Cu = rotl64(Ese, 2);
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

/* sha3 */

void sha3_compute256(uint8_t* output, const uint8_t* message, size_t msglen)
{
	keccak_state state;
	uint8_t hash[SHA3_256_RATE] = { 0 };
	size_t i;

	clear64(state.state, SHA3_STATE_SIZE);
	keccak_absorb(state.state, SHA3_256_RATE, message, msglen, SHA3_DOMAIN_ID);
	keccak_squeezeblocks(state.state, hash, 1, SHA3_256_RATE);

	for (i = 0; i < SHA3_256_HASH; ++i)
	{
		output[i] = hash[i];
	}
}

void sha3_compute512(uint8_t* output, const uint8_t* message, size_t msglen)
{
	keccak_state state;
	uint8_t hash[SHA3_512_RATE];
	size_t i;

	clear64(state.state, SHA3_STATE_SIZE);
	keccak_absorb(state.state, SHA3_512_RATE, message, msglen, SHA3_DOMAIN_ID);
	keccak_squeezeblocks(state.state, hash, 1, SHA3_512_RATE);

	for (i = 0; i < 64; ++i)
	{
		output[i] = hash[i];
	}
}

void sha3_blockupdate(keccak_state* state, size_t rate, const uint8_t* message, size_t nblocks)
{
	size_t i;

	while (nblocks > 0)
	{
		for (i = 0; i < rate / 8; ++i)
		{
			state->state[i] ^= le8to64(message + (sizeof(uint64_t) * i));
		}

		keccak_permute(state->state);
		message += rate;
		--nblocks;
	}
}

void sha3_finalize(keccak_state* state, size_t rate, const uint8_t* message, size_t msglen, uint8_t* output)
{
	uint8_t msg[SHA3_STATE_SIZE * sizeof(uint64_t)] = { 0 };
	size_t i;

	if (msglen >= rate)
	{
		sha3_blockupdate(state, rate, message, msglen / rate);
		message += (msglen / rate) * rate;
		msglen = (msglen % rate);
	}

	for (i = 0; i < msglen; ++i)
	{
		msg[i] = message[i];
	}

	msg[msglen] = SHA3_DOMAIN_ID;
	msg[rate - 1] |= 128U;

	for (i = 0; i < rate / sizeof(uint64_t); ++i)
	{
		state->state[i] ^= le8to64(msg + (sizeof(uint64_t) * i));
	}

	keccak_permute(state->state);
	msglen = ((((SHA3_STATE_SIZE * sizeof(uint64_t)) - rate) / 2) / 8);

	for (i = 0; i < msglen; ++i)
	{
		le64to8(output, state->state[i]);
		output += 8;
	}
}

void sha3_initialize(keccak_state* state)
{
	clear64(state->state, SHA3_STATE_SIZE);
}

/* shake */

void shake128(uint8_t* output, size_t outputlen, const uint8_t* key, size_t keylen)
{
	const size_t nblocks = outputlen / SHAKE_128_RATE;
	keccak_state state;
	uint8_t hash[SHAKE_128_RATE] = { 0 };
	size_t i;

	clear64(state.state, SHA3_STATE_SIZE);
	shake128_initialize(&state, key, keylen);
	shake128_squeezeblocks(&state, output, nblocks);

	output += (nblocks * SHAKE_128_RATE);
	outputlen -= (nblocks * SHAKE_128_RATE);

	if (outputlen != 0)
	{
		shake128_squeezeblocks(&state, hash, 1);

		for (i = 0; i < outputlen; ++i)
		{
			output[i] = hash[i];
		}
	}
}

void shake128_initialize(keccak_state* state, const uint8_t* key, size_t keylen)
{
	keccak_absorb(state->state, SHAKE_128_RATE, key, keylen, SHAKE_DOMAIN_ID);
}

void shake128_squeezeblocks(keccak_state* state, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(state->state, output, nblocks, SHAKE_128_RATE);
}

void shake256(uint8_t* output, size_t outputlen, const uint8_t* key, size_t keylen)
{
	const size_t nblocks = outputlen / SHAKE_256_RATE;
	keccak_state state;
	uint8_t hash[SHAKE_256_RATE] = { 0 };
	size_t i;

	clear64(state.state, SHA3_STATE_SIZE);
	shake256_initialize(&state, key, keylen);
	shake256_squeezeblocks(&state, output, nblocks);

	output += (nblocks * SHAKE_256_RATE);
	outputlen -= (nblocks * SHAKE_256_RATE);

	if (outputlen != 0)
	{
		shake256_squeezeblocks(&state, hash, 1);

		for (i = 0; i < outputlen; ++i)
		{
			output[i] = hash[i];
		}
	}
}

void shake256_initialize(keccak_state* state, const uint8_t* key, size_t keylen)
{
	keccak_absorb(state->state, SHAKE_256_RATE, key, keylen, SHAKE_DOMAIN_ID);
}

void shake256_squeezeblocks(keccak_state* state, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(state->state, output, nblocks, SHAKE_256_RATE);
}

void shake512(uint8_t* output, size_t outputlen, const uint8_t* key, size_t keylen)
{
	const size_t nblocks = outputlen / SHAKE_512_RATE;
	keccak_state state;
	uint8_t hash[SHAKE_512_RATE] = { 0 };
	size_t i;

	clear64(state.state, SHA3_STATE_SIZE);
	shake512_initialize(&state, key, keylen);
	shake512_squeezeblocks(&state, output, nblocks);

	output += (nblocks * SHAKE_512_RATE);
	outputlen -= (nblocks * SHAKE_512_RATE);

	if (outputlen != 0)
	{
		shake512_squeezeblocks(&state, hash, 1);

		for (i = 0; i < outputlen; ++i)
		{
			output[i] = hash[i];
		}
	}
}

void shake512_initialize(keccak_state* state, const uint8_t* key, size_t keylen)
{
	keccak_absorb(state->state, SHAKE_512_RATE, key, keylen, SHAKE_DOMAIN_ID);
}

void shake512_squeezeblocks(keccak_state* state, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(state->state, output, nblocks, SHAKE_512_RATE);
}

/* cshake */

void cshake128(uint8_t* output, size_t outputlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen)
{
	const size_t nblocks = outputlen / CSHAKE_128_RATE;
	keccak_state state;
	uint8_t hash[CSHAKE_128_RATE] = { 0 };
	size_t i;

	clear64(state.state, SHA3_STATE_SIZE);

	if (customlen + namelen != 0)
	{
		cshake128_initialize(&state, key, keylen, name, namelen, custom, customlen);
	}
	else
	{
		shake128_initialize(&state, key, keylen);
	}

	cshake128_squeezeblocks(&state, output, nblocks);

	output += (nblocks * CSHAKE_128_RATE);
	outputlen -= (nblocks * CSHAKE_128_RATE);

	if (outputlen != 0)
	{
		cshake128_squeezeblocks(&state, hash, 1);

		for (i = 0; i < outputlen; ++i)
		{
			output[i] = hash[i];
		}
	}
}

void cshake128_initialize(keccak_state* state, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen)
{
	uint8_t pad[SHAKE_STATE_SIZE * sizeof(uint64_t)];
	size_t i;
	size_t j;
	size_t offset;

	offset = left_encode(pad, CSHAKE_128_RATE);
	offset += left_encode(pad + offset, namelen * 8);

	if (namelen != 0)
	{
		for (i = 0; i < namelen; ++i)
		{
			if (offset == CSHAKE_128_RATE)
			{
				for (j = 0; j < CSHAKE_128_RATE / sizeof(uint64_t); ++j)
				{
					state->state[j] ^= le8to64(pad + (j * sizeof(uint64_t)));
				}

				keccak_permute(state->state);
				offset = 0;
			}

			pad[offset] = name[i];
			++offset;
		}
	}

	offset += left_encode(pad + offset, customlen * 8);

	if (customlen != 0)
	{
		for (i = 0; i < customlen; ++i)
		{
			if (offset == CSHAKE_128_RATE)
			{
				for (j = 0; j < CSHAKE_128_RATE / sizeof(uint64_t); ++j)
				{
					state->state[j] ^= le8to64(pad + (j * sizeof(uint64_t)));
				}

				keccak_permute(state->state);
				offset = 0;
			}

			pad[offset] = custom[i];
			++offset;
		}
	}

	clear8(pad + offset, CSHAKE_128_RATE - offset);

	for (i = 0; i < CSHAKE_128_RATE / sizeof(uint64_t); ++i)
	{
		state->state[i] ^= le8to64(pad + (i * sizeof(uint64_t)));
	}

	/* transform the domain string */
	keccak_permute(state->state);

	/* initialize the key */
	cshake128_update(state, key, keylen);
}

void cshake128_squeezeblocks(keccak_state* state, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(state->state, output, nblocks, CSHAKE_128_RATE);
}

void cshake128_update(keccak_state* state, const uint8_t* key, size_t keylen)
{
	keccak_absorb(state->state, CSHAKE_128_RATE, key, keylen, CSHAKE_DOMAIN_ID);
}

void cshake256(uint8_t* output, size_t outputlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen)
{
	const size_t nblocks = outputlen / CSHAKE_256_RATE;
	keccak_state kstate;
	uint8_t hash[CSHAKE_256_RATE] = { 0 };
	size_t i;

	clear64(kstate.state, SHA3_STATE_SIZE);

	if (customlen + namelen != 0)
	{
		cshake256_initialize(&kstate, key, keylen, name, namelen, custom, customlen);
	}
	else
	{
		shake256_initialize(&kstate, key, keylen);
	}

	cshake256_squeezeblocks(&kstate, output, nblocks);

	output += (nblocks * CSHAKE_256_RATE);
	outputlen -= (nblocks * CSHAKE_256_RATE);

	if (outputlen != 0)
	{
		cshake256_squeezeblocks(&kstate, hash, 1);

		for (i = 0; i < outputlen; ++i)
		{
			output[i] = hash[i];
		}
	}
}

void cshake256_initialize(keccak_state* state, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen)
{
	uint8_t pad[SHAKE_STATE_SIZE * sizeof(uint64_t)];
	size_t i;
	size_t j;
	size_t offset;

	offset = left_encode(pad, CSHAKE_256_RATE);
	offset += left_encode(pad + offset, namelen * 8);

	if (namelen != 0)
	{
		for (i = 0; i < namelen; ++i)
		{
			if (offset == CSHAKE_256_RATE)
			{
				for (j = 0; j < CSHAKE_256_RATE / sizeof(uint64_t); ++j)
				{
					state->state[j] ^= le8to64(pad + (j * sizeof(uint64_t)));
				}

				keccak_permute(state->state);
				offset = 0;
			}

			pad[offset] = name[i];
			++offset;
		}
	}

	offset += left_encode(pad + offset, customlen * 8);

	if (customlen != 0)
	{
		for (i = 0; i < customlen; ++i)
		{
			if (offset == CSHAKE_256_RATE)
			{
				for (j = 0; j < CSHAKE_256_RATE / sizeof(uint64_t); ++j)
				{
					state->state[j] ^= le8to64(pad + (j * sizeof(uint64_t)));
				}

				keccak_permute(state->state);
				offset = 0;
			}

			pad[offset] = custom[i];
			++offset;
		}
	}

	clear8(pad + offset, CSHAKE_256_RATE - offset);

	for (i = 0; i < CSHAKE_256_RATE / sizeof(uint64_t); ++i)
	{
		state->state[i] ^= le8to64(pad + (i * sizeof(uint64_t)));
	}

	/* transform the domain string */
	keccak_permute(state->state);

	/* initialize the key */
	cshake256_update(state, key, keylen);
}

void cshake256_squeezeblocks(keccak_state* state, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(state->state, output, nblocks, CSHAKE_256_RATE);
}

void cshake256_update(keccak_state* state, const uint8_t* key, size_t keylen)
{
	keccak_absorb(state->state, CSHAKE_256_RATE, key, keylen, CSHAKE_DOMAIN_ID);
}

void cshake512(uint8_t* output, size_t outputlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen)
{
	const size_t nblocks = outputlen / CSHAKE_512_RATE;
	keccak_state state;
	uint8_t hash[CSHAKE_512_RATE] = { 0 };
	size_t i;

	clear64(state.state, SHA3_STATE_SIZE);

	if (customlen + namelen != 0)
	{
		cshake512_initialize(&state, key, keylen, name, namelen, custom, customlen);
	}
	else
	{
		shake512_initialize(&state, key, keylen);
	}

	cshake512_squeezeblocks(&state, output, nblocks);

	output += (nblocks * CSHAKE_512_RATE);
	outputlen -= (nblocks * CSHAKE_512_RATE);

	if (outputlen != 0)
	{
		cshake512_squeezeblocks(&state, hash, 1);

		for (i = 0; i < outputlen; ++i)
		{
			output[i] = hash[i];
		}
	}
}

void cshake512_initialize(keccak_state* state, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen)
{
	uint8_t pad[SHAKE_STATE_SIZE * sizeof(uint64_t)];
	size_t i;
	size_t j;
	size_t offset;

	offset = left_encode(pad, CSHAKE_512_RATE);
	offset += left_encode(pad + offset, namelen * 8);

	if (namelen != 0)
	{
		for (i = 0; i < namelen; ++i)
		{
			if (offset == CSHAKE_512_RATE)
			{
				for (j = 0; j < CSHAKE_512_RATE / sizeof(uint64_t); ++j)
				{
					state->state[j] ^= le8to64(pad + (j * sizeof(uint64_t)));
				}

				keccak_permute(state->state);
				offset = 0;
			}

			pad[offset] = name[i];
			++offset;
		}
	}

	offset += left_encode(pad + offset, customlen * 8);

	if (customlen != 0)
	{
		for (i = 0; i < customlen; ++i)
		{
			if (offset == CSHAKE_512_RATE)
			{
				for (j = 0; j < CSHAKE_512_RATE / sizeof(uint64_t); ++j)
				{
					state->state[j] ^= le8to64(pad + (j * sizeof(uint64_t)));
				}

				keccak_permute(state->state);
				offset = 0;
			}

			pad[offset] = custom[i];
			++offset;
		}
	}

	clear8(pad + offset, CSHAKE_512_RATE - offset);

	for (i = 0; i < CSHAKE_512_RATE / sizeof(uint64_t); ++i)
	{
		state->state[i] ^= le8to64(pad + (i * sizeof(uint64_t)));
	}

	/* transform the domain string */
	keccak_permute(state->state);

	/* initialize the key */
	cshake512_update(state, key, keylen);
}

void cshake512_squeezeblocks(keccak_state* state, uint8_t* output, size_t nblocks)
{
	keccak_squeezeblocks(state->state, output, nblocks, CSHAKE_512_RATE);
}

void cshake512_update(keccak_state* state, const uint8_t* key, size_t keylen)
{
	keccak_absorb(state->state, CSHAKE_512_RATE, key, keylen, CSHAKE_DOMAIN_ID);
}

/* kmac */

void kmac128(uint8_t* output, size_t outputlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen)
{
	keccak_state state;

	clear64(state.state, KMAC_STATE_SIZE);
	kmac128_initialize(&state, key, keylen, custom, customlen);

	if (msglen >= KMAC_128_RATE)
	{
		const size_t rndlen = (msglen / KMAC_128_RATE) * KMAC_128_RATE;
		kmac128_blockupdate(&state, message, rndlen / KMAC_128_RATE);
		msglen -= rndlen;
		message += rndlen;
	}

	kmac128_finalize(&state, output, outputlen, message, msglen);
}

void kmac128_blockupdate(keccak_state* state, const uint8_t* message, size_t nblocks)
{
	size_t i;

	while (nblocks > 0)
	{
		for (i = 0; i < KMAC_128_RATE / sizeof(uint64_t); ++i)
		{
			state->state[i] ^= le8to64(message + (sizeof(uint64_t) * i));
		}

		keccak_permute(state->state);

		--nblocks;
		message += KMAC_128_RATE;
	}
}

void kmac128_finalize(keccak_state* state, uint8_t* output, size_t outputlen, const uint8_t* message, size_t msglen)
{
	uint8_t buf[sizeof(size_t) + 1] = { 0 };
	uint8_t pad[KMAC_STATE_SIZE * sizeof(uint64_t)] = { 0 };
	size_t outbitlen;
	size_t i;

	for (i = 0; i < msglen; ++i)
	{
		pad[i] = message[i];
	}

	outbitlen = right_encode(buf, outputlen * 8);

	for (i = 0; i < outbitlen; ++i)
	{
		pad[msglen + i] = buf[i];
	}

	pad[msglen + outbitlen] = KMAC_DOMAIN_ID;
	pad[KMAC_128_RATE - 1] |= 128U;

	for (i = 0; i < KMAC_128_RATE / sizeof(uint64_t); ++i)
	{
		state->state[i] ^= le8to64(pad + (i * sizeof(uint64_t)));
	}

	while (outputlen >= KMAC_128_RATE)
	{
		keccak_squeezeblocks(state->state, pad, 1, KMAC_128_RATE);

		for (i = 0; i < KMAC_128_RATE; ++i)
		{
			output[i] = pad[i];
		}

		output += KMAC_128_RATE;
		outputlen -= KMAC_128_RATE;
	}

	if (outputlen > 0)
	{
		keccak_squeezeblocks(state->state, pad, 1, KMAC_128_RATE);

		for (i = 0; i < outputlen; ++i)
		{
			output[i] = pad[i];
		}
	}
}

void kmac128_initialize(keccak_state* state, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen)
{
	uint8_t pad[KMAC_STATE_SIZE * sizeof(uint64_t)] = { 0 };
	const uint8_t name[] = { 0x4B, 0x4D, 0x41, 0x43 };
	size_t offset;
	size_t i;
	size_t j;

	clear64(state->state, KMAC_STATE_SIZE);

	/* stage 1: name + custom */

	offset = left_encode(pad, KMAC_128_RATE);
	offset += left_encode(pad + offset, sizeof(name) * 8);

	for (i = 0; i < sizeof(name); ++i)
	{
		pad[offset + i] = name[i];
	}

	offset += sizeof(name);
	offset += left_encode(pad + offset, customlen * 8);

	for (i = 0; i < customlen; ++i)
	{
		if (offset == KMAC_128_RATE)
		{
			for (j = 0; j < KMAC_128_RATE / sizeof(uint64_t); ++j)
			{
				state->state[j] ^= le8to64(pad + (j * sizeof(uint64_t)));
			}

			keccak_permute(state->state);
			offset = 0;
		}

		pad[offset] = custom[i];
		++offset;
	}

	clear8(pad + offset, KMAC_128_RATE - offset);

	for (i = 0; i < KMAC_128_RATE / sizeof(uint64_t); ++i)
	{
		state->state[i] = le8to64(pad + (i * sizeof(uint64_t)));
	}

	keccak_permute(state->state);

	/* stage 2: key */

	clear8(pad, KMAC_128_RATE);
	offset = left_encode(pad, KMAC_128_RATE);
	offset += left_encode(pad + offset, keylen * 8);

	for (i = 0; i < keylen; ++i)
	{
		if (offset == KMAC_128_RATE)
		{
			for (j = 0; j < KMAC_128_RATE / sizeof(uint64_t); ++j)
			{
				state->state[j] ^= le8to64(pad + (j * sizeof(uint64_t)));
			}

			keccak_permute(state->state);
			offset = 0;
		}

		pad[offset] = key[i];
		++offset;
	}

	clear8(pad + offset, KMAC_128_RATE - offset);

	for (i = 0; i < KMAC_128_RATE / sizeof(uint64_t); ++i)
	{
		state->state[i] ^= le8to64(pad + (i * sizeof(uint64_t)));
	}

	keccak_permute(state->state);
}

void kmac256(uint8_t* output, size_t outputlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen)
{
	keccak_state state;

	clear64(state.state, KMAC_STATE_SIZE);
	kmac256_initialize(&state, key, keylen, custom, customlen);

	if (msglen >= KMAC_256_RATE)
	{
		const size_t rndlen = (msglen / KMAC_256_RATE) * KMAC_256_RATE;
		kmac256_blockupdate(&state, message, rndlen / KMAC_256_RATE);
		msglen -= rndlen;
		message += rndlen;
	}

	kmac256_finalize(&state, output, outputlen, message, msglen);
}

void kmac256_blockupdate(keccak_state* state, const uint8_t* message, size_t nblocks)
{
	size_t i;

	while (nblocks > 0)
	{
		for (i = 0; i < KMAC_256_RATE / sizeof(uint64_t); ++i)
		{
			state->state[i] ^= le8to64(message + (sizeof(uint64_t) * i));
		}

		keccak_permute(state->state);

		--nblocks;
		message += KMAC_256_RATE;
	}
}

void kmac256_finalize(keccak_state* state, uint8_t* output, size_t outputlen, const uint8_t* message, size_t msglen)
{
	uint8_t buf[sizeof(size_t) + 1] = { 0 };
	uint8_t pad[KMAC_STATE_SIZE * sizeof(uint64_t)] = { 0 };
	size_t outbitlen;
	size_t i;

	for (i = 0; i < msglen; ++i)
	{
		pad[i] = message[i];
	}

	outbitlen = right_encode(buf, outputlen * 8);

	for (i = 0; i < outbitlen; ++i)
	{
		pad[msglen + i] = buf[i];
	}

	pad[msglen + outbitlen] = KMAC_DOMAIN_ID;
	pad[KMAC_256_RATE - 1] |= 128U;

	for (i = 0; i < KMAC_256_RATE / sizeof(uint64_t); ++i)
	{
		state->state[i] ^= le8to64(pad + (i * sizeof(uint64_t)));
	}

	while (outputlen >= KMAC_256_RATE)
	{
		keccak_squeezeblocks(state->state, pad, 1, KMAC_256_RATE);

		for (i = 0; i < KMAC_256_RATE; ++i)
		{
			output[i] = pad[i];
		}

		output += KMAC_256_RATE;
		outputlen -= KMAC_256_RATE;
	}

	if (outputlen > 0)
	{
		keccak_squeezeblocks(state->state, pad, 1, KMAC_256_RATE);

		for (i = 0; i < outputlen; ++i)
		{
			output[i] = pad[i];
		}
	}
}

void kmac256_initialize(keccak_state* state, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen)
{
	uint8_t pad[KMAC_STATE_SIZE * sizeof(uint64_t)] = { 0 };
	const uint8_t name[] = { 0x4B, 0x4D, 0x41, 0x43 };
	size_t offset;
	size_t i;
	size_t j;

	clear64(state->state, KMAC_STATE_SIZE);
	clear8(pad, KMAC_256_RATE);

	/* stage 1: name + custom */

	offset = left_encode(pad, KMAC_256_RATE);
	offset += left_encode(pad + offset, sizeof(name) * 8);

	for (i = 0; i < sizeof(name); ++i)
	{
		pad[offset + i] = name[i];
	}

	offset += sizeof(name);
	offset += left_encode(pad + offset, customlen * 8);

	for (i = 0; i < customlen; ++i)
	{
		if (offset == KMAC_256_RATE)
		{
			for (j = 0; j < KMAC_256_RATE / sizeof(uint64_t); ++j)
			{
				state->state[j] ^= le8to64(pad + (j * 8));
			}

			keccak_permute(state->state);
			offset = 0;
		}

		pad[offset] = custom[i];
		++offset;
	}

	clear8(pad + offset, KMAC_256_RATE - offset);

	for (i = 0; i < KMAC_256_RATE / sizeof(uint64_t); ++i)
	{
		state->state[i] = le8to64(pad + (i * sizeof(uint64_t)));
	}

	keccak_permute(state->state);

	/* stage 2: key */

	clear8(pad, KMAC_256_RATE);
	offset = left_encode(pad, KMAC_256_RATE);
	offset += left_encode(pad + offset, keylen * 8);

	for (i = 0; i < keylen; ++i)
	{
		if (offset == KMAC_256_RATE)
		{
			for (j = 0; j < KMAC_256_RATE / sizeof(uint64_t); ++j)
			{
				state->state[j] ^= le8to64(pad + (j * sizeof(uint64_t)));
			}

			keccak_permute(state->state);
			offset = 0;
		}

		pad[offset] = key[i];
		++offset;
	}

	clear8(pad + offset, KMAC_256_RATE - offset);

	for (i = 0; i < KMAC_256_RATE / sizeof(uint64_t); ++i)
	{
		state->state[i] ^= le8to64(pad + (i * sizeof(uint64_t)));
	}

	keccak_permute(state->state);
}

void kmac512(uint8_t* output, size_t outputlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen)
{
	keccak_state state;

	clear64(state.state, KMAC_STATE_SIZE);
	kmac512_initialize(&state, key, keylen, custom, customlen);

	if (msglen >= KMAC_512_RATE)
	{
		const size_t rndlen = (msglen / KMAC_512_RATE) * KMAC_512_RATE;
		kmac512_blockupdate(&state, message, rndlen / KMAC_512_RATE);
		msglen -= rndlen;
		message += rndlen;
	}

	kmac512_finalize(&state, output, outputlen, message, msglen);
}

void kmac512_blockupdate(keccak_state* state, const uint8_t* message, size_t nblocks)
{
	size_t i;

	while (nblocks > 0)
	{
		for (i = 0; i < KMAC_512_RATE / sizeof(uint64_t); ++i)
		{
			state->state[i] ^= le8to64(message + (sizeof(uint64_t) * i));
		}

		keccak_permute(state->state);

		--nblocks;
		message += KMAC_512_RATE;
	}
}

void kmac512_finalize(keccak_state* state, uint8_t* output, size_t outputlen, const uint8_t* message, size_t msglen)
{
	uint8_t buf[sizeof(size_t) + 1] = { 0 };
	uint8_t pad[KMAC_STATE_SIZE * sizeof(uint64_t)] = { 0 };
	size_t outbitlen;
	size_t i;

	clear8(pad, KMAC_512_RATE);

	for (i = 0; i < msglen; ++i)
	{
		pad[i] = message[i];
	}

	outbitlen = right_encode(buf, outputlen * 8);

	for (i = 0; i < outbitlen; ++i)
	{
		pad[msglen + i] = buf[i];
	}

	pad[msglen + outbitlen] = KMAC_DOMAIN_ID;
	pad[KMAC_512_RATE - 1] |= 128U;

	for (i = 0; i < KMAC_512_RATE / sizeof(uint64_t); ++i)
	{
		state->state[i] ^= le8to64(pad + (i * sizeof(uint64_t)));
	}

	while (outputlen >= KMAC_512_RATE)
	{
		keccak_squeezeblocks(state->state, pad, 1, KMAC_512_RATE);

		for (i = 0; i < KMAC_512_RATE; ++i)
		{
			output[i] = pad[i];
		}

		output += KMAC_512_RATE;
		outputlen -= KMAC_512_RATE;
	}

	if (outputlen > 0)
	{
		keccak_squeezeblocks(state->state, pad, 1, KMAC_512_RATE);

		for (i = 0; i < outputlen; ++i)
		{
			output[i] = pad[i];
		}
	}
}

void kmac512_initialize(keccak_state* state, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen)
{
	uint8_t pad[KMAC_STATE_SIZE * sizeof(uint64_t)] = { 0 };
	const uint8_t name[] = { 0x4B, 0x4D, 0x41, 0x43 };
	size_t offset;
	size_t i;
	size_t j;

	clear64(state->state, KMAC_STATE_SIZE);

	/* stage 1: name + custom */

	offset = left_encode(pad, KMAC_512_RATE);
	offset += left_encode(pad + offset, sizeof(name) * 8);

	for (i = 0; i < sizeof(name); ++i)
	{
		pad[offset + i] = name[i];
	}

	offset += sizeof(name);
	offset += left_encode(pad + offset, customlen * 8);

	for (i = 0; i < customlen; ++i)
	{
		if (offset == KMAC_512_RATE)
		{
			for (j = 0; j < KMAC_512_RATE / sizeof(uint64_t); ++j)
			{
				state->state[j] ^= le8to64(pad + (j * sizeof(uint64_t)));
			}

			keccak_permute(state->state);
			offset = 0;
		}

		pad[offset] = custom[i];
		++offset;
	}

	clear8(pad + offset, KMAC_512_RATE - offset);

	for (i = 0; i < KMAC_512_RATE / 8; ++i)
	{
		state->state[i] = le8to64(pad + (i * 8));
	}

	keccak_permute(state->state);

	/* stage 2: key */

	clear8(pad, KMAC_512_RATE);
	offset = left_encode(pad, KMAC_512_RATE);
	offset += left_encode(pad + offset, keylen * 8);

	for (i = 0; i < keylen; ++i)
	{
		if (offset == KMAC_512_RATE)
		{
			for (j = 0; j < KMAC_512_RATE / sizeof(uint64_t); ++j)
			{
				state->state[j] ^= le8to64(pad + (j * sizeof(uint64_t)));
			}

			keccak_permute(state->state);
			offset = 0;
		}

		pad[offset] = key[i];
		++offset;
	}

	clear8(pad + offset, KMAC_512_RATE - offset);

	for (i = 0; i < KMAC_512_RATE / sizeof(uint64_t); ++i)
	{
		state->state[i] ^= le8to64(pad + (i * sizeof(uint64_t)));
	}

	keccak_permute(state->state);
}
