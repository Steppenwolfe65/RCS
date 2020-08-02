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
	hex_to_bin("0FDCA3082A654CD1E7B3926C4BD12264449D39E1E937F75A1398E6C3EDD1BD2E67E47E01260C8B895DDF580EB99DDBCE46D085510E211D7D4ED19C9BB09B9BB2", exp1, sizeof(exp1));
	hex_to_bin("58436581A0E797EC095E7BE3D51A90F35ABA2C34980BEAB539CDBC87AA19CB07FB5C7DD5DF98414BE3D5DDA21643E26BD1D86E28A1EBE7B970460C4ED7B6C8A0", exp2, sizeof(exp2));
#else
	/* rcsc256k256 */
	hex_to_bin("7940917E9219A31248946F71647B15421535941574F84F79F6110C1F2F776D03CE628327C50E0893EF608FA819E46E2521CFD604B26326261A40030B88271914", exp1, sizeof(exp1));
	hex_to_bin("ABF3574126DAA563B423B0EEEE9970FD0C8F060F65CB00CDC05BB0DC047DB2ADBE41BFB37765365D91C156691175F9DF042C82282EE3A399884F6C6E58150F60", exp2, sizeof(exp2));
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
	hex_to_bin("15BF458477AE0BC50E893348F33E08F2950003E0B760830F8BC850469E442639B1F09CA5273161DC72B2F7FD1131B4216198E88D0970A389F88C0D83E1D24023"
		"A43C9637E0BF51C92C769BDBC5C585C876F75C42F8D4AFC12612C0EAC2C40DEE", exp1, sizeof(exp1));
	hex_to_bin("71A1E7980B3767EAC7C863C21DA210104F34CB18DD625531988B13430579D9467E8A9FBCE1670CD1D92ECEF407A13987731D3E7F1C45F364AA4C1C14992C1B76"
		"9D43215761AF88B93246461653E10D3FF3C4934AB65AA104135BFAF1501DD700", exp2, sizeof(exp2));
#else
	/* rcsc512k512 */
	hex_to_bin("21E97A126E35BE731EF204E48248A2EEB01B692992F73786602F21031FBFB7C8CE73A1069C12C893662D7E461145EABAF4318FE147F3DF426326A11579CFF3CD"
		"9C6EB37475C57203374767226CBFCF5557B1CC8E647B97D0EE94124AAA612FA7", exp1, sizeof(exp1));
	hex_to_bin("B1DF351F3ED958C5884B82766359A73EDA5530688F2BB1BAC9C14F375F7CB7D29270006DFA9D3EB97F168FD19547EA3FD2E5F80E263C49F2776B5BB8EF15EC8A"
		"E05AD8063C5565BA4A544237A6F6DD4D784363F255895CD83D7FB5A200B5E357", exp2, sizeof(exp2));
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
