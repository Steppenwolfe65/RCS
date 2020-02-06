#include "rcs_kat.h"
#include "intutils.h"
#include "rcs.h"
#include "sha2.h"
#include "sha3.h"
#include "sysrand.h"
#include "testutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool rcs256_kat_test()
{
	uint8_t dec[RCS_BLOCK_SIZE] = { 0 };
	uint8_t enc1[RCS_BLOCK_SIZE + RCS256_MAC_LENGTH] = { 0 };
	uint8_t enc2[RCS_BLOCK_SIZE + RCS256_MAC_LENGTH] = { 0 };
	uint8_t exp1[RCS_BLOCK_SIZE + RCS256_MAC_LENGTH] = { 0 };
	uint8_t exp2[RCS_BLOCK_SIZE + RCS256_MAC_LENGTH] = { 0 };
	uint8_t key[RCS256_KEY_SIZE] = { 0 };
	uint8_t msg[RCS_BLOCK_SIZE] = { 0 };
	uint8_t nce[RCS_BLOCK_SIZE] = { 0 };
	uint8_t ncpy[RCS_BLOCK_SIZE] = { 0 };
	bool status;
	rcs_state state;

	/* vectors from CEX */
#ifdef RCS_HMAC_EXTENSION
	/* rcsc256h256 */
	hex_to_bin("9257E21FC45EC728EC630659C88483E23666EE4CE35114C94C1F82B3AA401100AB2FCABE5014AB6FCF059F39A95F88B86E27E0037EFA2C17480D40A093C52D52", exp1, sizeof(exp1));
	hex_to_bin("FF99512C5A343FFE71527FB19F3F3DF2E1C71D7626EDBAEA9C7621098B9927081911C02D3D96D700D60F127FFABB04D9EC7C1A1739D61E7952CFDEE5868E1E61", exp2, sizeof(exp2));
#else
	/* rcsc256k256 */
	hex_to_bin("27E3BDDDB08F97C132D646D7AC5AFB96FDD0C714A6212A294D593552D442F97F8C328773AAD85BB55C99B113122B3BA92341BE0E66181373AE734CB928217CA1", exp1, sizeof(exp1));
	hex_to_bin("2E87066D3E9CC88EAF6C6D380D8DBEE5B3484FA6136A33A5E2745CC5A2EEC2A75B4464A842E7A294EB98F541335992B790A8CF903677E49DD0EB71C9B244A6BB", exp2, sizeof(exp2));
#endif

	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", msg, sizeof(msg));
	hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0", nce, sizeof(nce));

	/* copy the nonce */
	memcpy(ncpy, nce, RCS_BLOCK_SIZE);

	/* initialize the key parameters struct, info is optional */
	rcs_keyparams kp = { key, RCS256_KEY_SIZE, nce };

	status = true;

	/* initialize the state and create the round-keys */
	rcs_initialize(&state, &kp, true, RCS256);

	/* test encryption */
	rcs_transform(&state, enc1, msg, sizeof(msg));

	if (are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		status = false;
	}

	/* test encryption and mac chaining */
	rcs_transform(&state, enc2, msg, sizeof(msg));

	if (are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	/* reset the nonce */
	kp.nonce = ncpy;

	/* initialize the state */
	rcs_initialize(&state, &kp, false, RCS256);

	/* test decryption */
	if (rcs_transform(&state, dec, enc1, sizeof(dec)) == false)
	{
		status = false;
	}

	if (are_equal8(dec, msg, sizeof(dec)) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rcs_dispose(&state);

	return status;
}

bool rcs512_kat_test()
{
	uint8_t dec[RCS_BLOCK_SIZE] = { 0 };
	uint8_t enc1[RCS_BLOCK_SIZE + RCS512_MAC_LENGTH] = { 0 };
	uint8_t enc2[RCS_BLOCK_SIZE + RCS512_MAC_LENGTH] = { 0 };
	uint8_t exp1[RCS_BLOCK_SIZE + RCS512_MAC_LENGTH] = { 0 };
	uint8_t exp2[RCS_BLOCK_SIZE + RCS512_MAC_LENGTH] = { 0 };
	uint8_t key[RCS512_KEY_SIZE] = { 0 };
	uint8_t msg[RCS_BLOCK_SIZE] = { 0 };
	uint8_t nce[RCS_BLOCK_SIZE] = { 0 };
	uint8_t ncpy[RCS_BLOCK_SIZE] = { 0 };
	bool status;
	rcs_state state;

	/* vectors from CEX */
#ifdef RCS_HMAC_EXTENSION
	/* rcsc512h512 */
	hex_to_bin("57049ECD1B6D11E6DA9C38160B05065D110B8961FF8ABDCACD9BFFB0EF207CDF17CA7BEE0E3BD529A17A124E2D5DAA199E0A0BC88A01EFDC1214B7CCD6090624"
		"8EECF6649B9CFC0B28AF9CA39AE4D1F9D9C5C5770028EB19E673ABADE06A4E59", exp1, sizeof(exp1));
	hex_to_bin("01142B7D11F79693DDE3CD27FEF98D5B439104494050AF78A741FE31582580DE15E292606E8ED01E35DBB70BD5808770F230882F47DFCBCB4B01C8833710F4C6"
		"AAA8EC0D3AB983DB75A2850025C1A10A88613F00C53F6B8D7B92E54FB287874A", exp2, sizeof(exp2));
#else
	/* rcsc512k512 */
	hex_to_bin("1FF03A20A6185BD94F6D4B4C013CA6756596BF66212523170D079031B43EBCF0DE6C0810F4903AB10A671832AE2F83B8DD26E40150DBC4488A8BBC734DBCC052"
		"7095A409CB6390E353AC5F303D354D077AF29591A9BB61C10697776D50F238C7", exp1, sizeof(exp1));
	hex_to_bin("3691A933C6C9FF40072401DABF751C710350361D5E635C4CF73C2390407AD5CD343DD647754879EF75DA8C95A8E91A0838ED8120A94196859E0C8A02CC877AF1"
		"1EC3546FCFA69AD6569945C407A2F1D959C92C9194FED045EF4EB71F74C08646", exp2, sizeof(exp2));
#endif

	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", msg, sizeof(msg));
	hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0", nce, sizeof(nce));

	/* copy the nonce */
	memcpy(ncpy, nce, sizeof(nce));

	/* initialize the key parameters struct, info is optional */
	rcs_keyparams kp = { key, RCS512_KEY_SIZE, nce };

	status = true;

	/* initialize the state and create the round-keys */
	rcs_initialize(&state, &kp, true, RCS512);

	/* test encryption */
	rcs_transform(&state, enc1, msg, sizeof(msg));

	if (are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		status = false;
	}

	/* test encryption and mac chaining */
	rcs_transform(&state, enc2, msg, sizeof(msg));

	if (are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	/* reset the nonce */
	kp.nonce = ncpy;

	/* initialize the state */
	rcs_initialize(&state, &kp, false, RCS512);

	/* test decryption */
	if (rcs_transform(&state, dec, enc1, sizeof(dec)) == false)
	{
		status = false;
	}

	if (are_equal8(dec, msg, sizeof(dec)) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	rcs_dispose(&state);

	return status;
}

bool rcs256_stress_test()
{
	uint8_t aad[20] = { 0 };
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[RCS256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ncopy[RCS_BLOCK_SIZE] = { 0 };
	uint8_t nonce[RCS_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	uint16_t mlen;
	size_t tctr;
	bool status;
	rcs_state state;

	tctr = 0;
	status = true;

	while (tctr < RCS_TEST_CYCLES)
	{
		mlen = 0;

		while (mlen == 0)
		{
			/* unlikely but this could return zero */
			sysrand_getbytes(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		}

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen + RCS256_MAC_LENGTH);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			clear8(dec, mlen);
			clear8(enc, mlen + RCS256_MAC_LENGTH);
			clear8(msg, mlen);
			memcpy(nonce, ncopy, RCS_BLOCK_SIZE);

			/* use a random sized message 1-65535 */
			sysrand_getbytes(msg, mlen);

			rcs_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* encrypt the message */
			rcs_initialize(&state, &kp1, true, RCS256);
			rcs_set_associated(&state, aad, sizeof(aad));

			if (rcs_transform(&state, enc, msg, mlen) == false)
			{
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, RCS_BLOCK_SIZE);

			/* decrypt the message */
			rcs_initialize(&state, &kp1, false, RCS256);
			rcs_set_associated(&state, aad, sizeof(aad));

			if (rcs_transform(&state, dec, enc, mlen) == false)
			{
				status = false;
			}

			/* compare decryption output to message */
			if (are_equal8(dec, msg, mlen) == false)
			{
				status = false;
			}

			free(dec);
			free(enc);
			free(msg);

			++tctr;
		}
		else
		{
			status = false;
			break;
		}
	}

	return status;
}

bool rcs512_stress_test()
{
	uint8_t aad[20] = { 0 };
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[RCS512_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ncopy[RCS_BLOCK_SIZE] = { 0 };
	uint8_t nonce[RCS_BLOCK_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	uint16_t mlen;
	size_t tctr;
	bool status;
	rcs_state state;

	tctr = 0;
	status = true;

	while (tctr < RCS_TEST_CYCLES)
	{
		mlen = 0;

		while (mlen == 0)
		{
			/* unlikely but this could return zero */
			sysrand_getbytes(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		}

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen + RCS512_MAC_LENGTH);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			clear8(dec, mlen);
			clear8(enc, mlen + RCS512_MAC_LENGTH);
			clear8(msg, mlen);
			memcpy(nonce, ncopy, RCS_BLOCK_SIZE);

			/* use a random sized message 1-65535 */
			sysrand_getbytes(msg, mlen);

			rcs_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* encrypt the message */
			rcs_initialize(&state, &kp1, true, RCS512);
			rcs_set_associated(&state, aad, sizeof(aad));

			if (rcs_transform(&state, enc, msg, mlen) == false)
			{
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, RCS_BLOCK_SIZE);

			/* decrypt the message */
			rcs_initialize(&state, &kp1, false, RCS512);
			rcs_set_associated(&state, aad, sizeof(aad));

			if (rcs_transform(&state, dec, enc, mlen) == false)
			{
				status = false;
			}

			/* compare decryption output to message */
			if (are_equal8(dec, msg, mlen) == false)
			{
				status = false;
			}

			free(dec);
			free(enc);
			free(msg);

			++tctr;
		}
		else
		{
			status = false;
			break;
		}
	}

	return status;
}
