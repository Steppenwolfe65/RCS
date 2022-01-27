#include "rcs_test.h"
#include "intutils.h"
#include "csp.h"
#include "testutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool qsctest_rcs256_kat()
{
#if defined(QSC_RCS_AUTHENTICATED)
	uint8_t ad[20] = { 0 };
	uint8_t enc1[32 + QSC_RCS256_MAC_SIZE] = { 0 };
	uint8_t enc2[32 + QSC_RCS256_MAC_SIZE] = { 0 };
	uint8_t exp1[32 + QSC_RCS256_MAC_SIZE] = { 0 };
	uint8_t exp2[32 + QSC_RCS256_MAC_SIZE] = { 0 };
	uint8_t ncpy[QSC_RCS_NONCE_SIZE] = { 0 };
#else
	uint8_t enc1[32] = { 0 };
	uint8_t exp1[32] = { 0 };
#endif

	uint8_t dec[32] = { 0 };
	uint8_t key[QSC_RCS256_KEY_SIZE] = { 0 };
	uint8_t msg[32] = { 0 };
	uint8_t nce[QSC_RCS_NONCE_SIZE] = { 0 };

	bool status;
	qsc_rcs_state state;

	/* vectors from CEX */

	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", msg, sizeof(msg));
	qsctest_hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0", nce, sizeof(nce));

#if defined(QSC_RCS_AUTHENTICATED)
#	if defined(QSC_RCS_AUTH_KMACR12)
	/* rcsc256p256 */
	qsctest_hex_to_bin("D4E387B91DC17672FBF74AF42F28D16576DAE20AA03CA3D3D6711D3ED3821BF8"
		"A282FF629207678A430AA676CFA1C21C763FA0C950136FA7338E55B5CFDEA89F", exp1, sizeof(exp1));
	qsctest_hex_to_bin("7921324560D43CE63751293E280D638E50D60C6171BF6E78C"
		"3BC7B160E3E9BE54709E5670CC8C6664CFED35709620A6642A21EE1EC054588082D4933E15F86DD", exp2, sizeof(exp2));
#	else
	/* rcsc256k256 */
	qsctest_hex_to_bin("7940917E9219A31248946F71647B15421535941574F84F79F"
		"6110C1F2F776D03F38582F301390A6B8807C75914CE0CF410051D73CAE97D1D295CB0420146E179", exp1, sizeof(exp1));
	qsctest_hex_to_bin("ABF3574126DAA563B423B0EEEE9970FD0C8F060F65CB00CDC"
		"05BB0DC047DB2ADA2A39BEB441FCD4C5F83F1142F264EEFCBAAA51D7874A0E7DA0A7B285DFD55AA", exp2, sizeof(exp2));
#	endif
	memset(ad, 0x01, sizeof(ad));
	memcpy(ncpy, nce, QSC_RCS_NONCE_SIZE);
#else
	qsctest_hex_to_bin("9EF7D04279C5277366D2DDD3FBB47F0DFCB3994D6F43D7F3A782778838C56DB3", exp1, sizeof(exp1));
#endif

	/* initialize the key parameters struct, info is optional */
	qsc_rcs_keyparams kp = { key, QSC_RCS256_KEY_SIZE, nce };

	status = true;

	/* initialize the state and create the round-keys */
	qsc_rcs_initialize(&state, &kp, true);
	
#if defined(QSC_RCS_AUTHENTICATED)
	/* set associated data */
	qsc_rcs_set_associated(&state, ad, sizeof(ad));
#endif

	/* test encryption */
	qsc_rcs_transform(&state, enc1, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		qsctest_print_safe("Failure! rcs256_kat: cipher output does not match the known answer -RK1 \n");
		status = false;
	}

#if defined(QSC_RCS_AUTHENTICATED)

	/* test encryption and mac chaining */

	qsc_rcs_transform(&state, enc2, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		qsctest_print_safe("Failure! rcs256_kat: cipher output does not match the known answer -RK2 \n");
		status = false;
	}

	/* reset the nonce */
	kp.nonce = ncpy;

	/* initialize the state */
	qsc_rcs_initialize(&state, &kp, false);

	/* set associated data */
	qsc_rcs_set_associated(&state, ad, sizeof(ad));

	/* test decryption */

	if (qsc_rcs_transform(&state, dec, enc1, sizeof(dec)) == false)
	{
		qsctest_print_safe("Failure! rcs256_kat: authentication failure -RK3 \n");
		status = false;
	}

	if (qsc_intutils_are_equal8(dec, msg, sizeof(dec)) == false)
	{
		qsctest_print_safe("Failure! rcs256_kat: cipher output does not match the known answer -RK4 \n");
		status = false;
	}
#endif

	/* erase the round-key array and reset the state */
	qsc_rcs_dispose(&state);

	return status;
}

bool qsctest_rcs512_kat()
{
#if defined(QSC_RCS_AUTHENTICATED)
	uint8_t ad[20] = { 0 };
	uint8_t enc1[64 + QSC_RCS512_MAC_SIZE] = { 0 };
	uint8_t enc2[64 + QSC_RCS512_MAC_SIZE] = { 0 };
	uint8_t exp1[64 + QSC_RCS512_MAC_SIZE] = { 0 };
	uint8_t exp2[64 + QSC_RCS512_MAC_SIZE] = { 0 };
	uint8_t ncpy[QSC_RCS_NONCE_SIZE] = { 0 };
#else
	uint8_t enc1[64] = { 0 };
	uint8_t exp1[64] = { 0 };
#endif

	uint8_t dec[64] = { 0 };
	uint8_t key[QSC_RCS512_KEY_SIZE] = { 0 };
	uint8_t msg[64] = { 0 };
	uint8_t nce[QSC_RCS_NONCE_SIZE] = { 0 };
	bool status;
	qsc_rcs_state state;

	/* vectors from CEX */
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"
		"000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F", key, sizeof(key));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F"
		"101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F", msg, sizeof(msg));
	qsctest_hex_to_bin("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0", nce, sizeof(nce));

#if defined(QSC_RCS_AUTHENTICATED)
#	if defined(QSC_RCS_AUTH_KMACR12)
	/* rcsc512p512 */
	/* rcsc512p512 */
	qsctest_hex_to_bin("B83B8234D260FBBBA5CB52BD1B37B30EDC2705FC53A7B846EFE04CDA430F0405"
		"CB779CEA01B82D0407D9FA19AAB9D5969A93F35E245DD28A107A7A851EAF0DCE"
		"44875E52383407C3C21EBEC2412C7E84EFE9AB9AC5FB65D9AD209774DF9A589C"
		"D9142AFA79B46F5B52D4C066133FEBCD595C3ED50ABDCE9ACDC7E1EB3E107980", exp1, sizeof(exp1));
	qsctest_hex_to_bin("720F4AFC15C716643AEA680AF059FFA560E8CFA0BD70AF3C7C05552D5768D122"
		"3D19623EA202BC2136500BE6B9BFAFC8C840AB2E30E90FF343623AEBDE9BC00F"
		"744482F38748DDA73748822C521FF7298F22AA35ADC9F56EC3AAFD3DF99904CD"
		"B33489C684F17C06E861C6BED81EF8CAFA7C6479237298CBE98DECEFD204150C", exp2, sizeof(exp2));
#	else
	/* rcsc512k512 */
	qsctest_hex_to_bin("21E97A126E35BE731EF204E48248A2EEB01B692992F73786602F21031FBFB7C8"
		"A1CF250F2EC948D5985B92667349B72EFA751048AF0B919AE9E16F177F5C97F2"
		"C40E0D50727DC9528664F656270E99A4857D7A2C28F965EB9956658145AC9868"
		"F3FDE25C39EC9EEF0C6A7ED955CB3C2F44286CD253C9BE0CF3F389313C47E4B2", exp1, sizeof(exp1));
	qsctest_hex_to_bin("388270BF8DF03483BB287FFA527D81403F0362210FD525657C8541250DFFE3BA"
		"D1285FAB37A6821DA524F3F7FF7EFCB39C5B59E3897B177E45D6AA7F4BB5BE77"
		"9CB2429F4693DF70D38DBBCB00EE86172435C117D442171A8485A87BF1D7282F"
		"2D69032C85F1CD1A1FEE794843E0CED7616722A4B0937210E9023220B085EA18", exp2, sizeof(exp2));
#	endif
	memset(ad, 0x01, sizeof(ad));
	memcpy(ncpy, nce, sizeof(nce));
#else
	qsctest_hex_to_bin("8643251F3880261010BF195886C0496CC2EB07BB68D9F13BCBD266890467F47F"
		"57FA98C08031903D6539AC94B4F17E3A45A741159FF929B0540436FFE7A77E01", exp1, sizeof(exp1));
#endif

	/* initialize the key parameters struct, info is optional */
	qsc_rcs_keyparams kp = { key, QSC_RCS512_KEY_SIZE, nce };

	status = true;

	/* initialize the state and create the round-keys */
	qsc_rcs_initialize(&state, &kp, true);

#if defined(QSC_RCS_AUTHENTICATED)
	/* set associated data */
	qsc_rcs_set_associated(&state, ad, sizeof(ad));
#endif

	/* test encryption */
	qsc_rcs_transform(&state, enc1, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		qsctest_print_safe("Failure! rcs512_kat: cipher output does not match the known answer -RK1 \n");
		status = false;
	}

#if defined(QSC_RCS_AUTHENTICATED)

	/* test encryption and mac chaining */

	qsc_rcs_transform(&state, enc2, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		qsctest_print_safe("Failure! rcs512_kat: cipher output does not match the known answer -RK2 \n");
		status = false;
	}

	/* reset the nonce */
	kp.nonce = ncpy;

	/* initialize the state */
	qsc_rcs_initialize(&state, &kp, false);

	/* set associated data */
	qsc_rcs_set_associated(&state, ad, sizeof(ad));

	/* test decryption */

	if (qsc_rcs_transform(&state, dec, enc1, sizeof(dec)) == false)
	{
		qsctest_print_safe("Failure! rcs512_kat: authentication failure -RK3 \n");
		status = false;
	}

	if (qsc_intutils_are_equal8(dec, msg, sizeof(dec)) == false)
	{
		qsctest_print_safe("Failure! rcs512_kat: cipher output does not match the known answer -RK4 \n");
		status = false;
	}
#endif

	/* erase the round-key array and reset the state */
	qsc_rcs_dispose(&state);

	return status;
}

bool qsctest_rcs256_stress_test()
{
	uint8_t aad[20] = { 0 };
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RCS256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ncopy[QSC_RCS_NONCE_SIZE] = { 0 };
	uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	uint16_t mlen;
	size_t tctr;
	bool status;
	qsc_rcs_state state;

	tctr = 0;
	status = true;

	while (tctr < QSCTEST_RCS_TEST_CYCLES)
	{
		mlen = 0;

		while (mlen == 0)
		{
			/* unlikely but this could return zero */
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		}

#if defined(QSC_RCS_AUTHENTICATED)
		enc = (uint8_t*)malloc((size_t)mlen + QSC_RCS256_MAC_SIZE);
#else
		enc = (uint8_t*)malloc(mlen);
#endif

		dec = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
#if defined(QSC_RCS_AUTHENTICATED)
			qsc_intutils_clear8(enc, (size_t)mlen + QSC_RCS256_MAC_SIZE);
#else
			qsc_intutils_clear8(enc, mlen);
#endif
			qsc_intutils_clear8(msg, mlen);
			memcpy(nonce, ncopy, QSC_RCS_NONCE_SIZE);

			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			qsc_rcs_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* encrypt the message */
			qsc_rcs_initialize(&state, &kp1, true);

#if defined(QSC_RCS_AUTHENTICATED)
			qsc_rcs_set_associated(&state, aad, sizeof(aad));
#endif

			if (qsc_rcs_transform(&state, enc, msg, mlen) == false)
			{
				qsctest_print_safe("Failure! rcs256_stress_test: encryption failure -RS1 \n");
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, QSC_RCS_NONCE_SIZE);

			/* decrypt the message */
			qsc_rcs_initialize(&state, &kp1, false);

#if defined(QSC_RCS_AUTHENTICATED)
			qsc_rcs_set_associated(&state, aad, sizeof(aad));
#endif

			if (qsc_rcs_transform(&state, dec, enc, mlen) == false)
			{
				qsctest_print_safe("Failure! rcs256_stress_test: authentication failure -RS2 \n");
				status = false;
			}

			/* compare decryption output to message */
			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				qsctest_print_safe("Failure! rcs256_stress_test: decryption failure -RS3 \n");
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

bool qsctest_rcs512_stress_test()
{
	uint8_t aad[20] = { 0 };
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RCS512_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ncopy[QSC_RCS_NONCE_SIZE] = { 0 };
	uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	uint16_t mlen;
	size_t tctr;
	bool status;
	qsc_rcs_state state;

	tctr = 0;
	status = true;

	while (tctr < QSCTEST_RCS_TEST_CYCLES)
	{
		mlen = 0;

		while (mlen == 0)
		{
			/* unlikely but this could return zero */
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		}

#if defined(QSC_RCS_AUTHENTICATED)
		enc = (uint8_t*)malloc((size_t)mlen + QSC_RCS512_MAC_SIZE);
#else
		enc = (uint8_t*)malloc(mlen);
#endif

		dec = (uint8_t*)malloc(mlen);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
#if defined(QSC_RCS_AUTHENTICATED)
			qsc_intutils_clear8(enc, (size_t)mlen + QSC_RCS512_MAC_SIZE);
#else
			qsc_intutils_clear8(enc, mlen);
#endif
			qsc_intutils_clear8(msg, mlen);
			memcpy(nonce, ncopy, QSC_RCS_NONCE_SIZE);

			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			qsc_rcs_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* encrypt the message */
			qsc_rcs_initialize(&state, &kp1, true);

#if defined(QSC_RCS_AUTHENTICATED)
			qsc_rcs_set_associated(&state, aad, sizeof(aad));
#endif

			if (qsc_rcs_transform(&state, enc, msg, mlen) == false)
			{
				qsctest_print_safe("Failure! rcs512_stress_test: encryption failure -RS1 \n");
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, QSC_RCS_NONCE_SIZE);

			/* decrypt the message */
			qsc_rcs_initialize(&state, &kp1, false);

#if defined(QSC_RCS_AUTHENTICATED)
			qsc_rcs_set_associated(&state, aad, sizeof(aad));
#endif

			if (qsc_rcs_transform(&state, dec, enc, mlen) == false)
			{
				qsctest_print_safe("Failure! rcs512_stress_test: authentication failure -RS2 \n");
				status = false;
			}

			/* compare decryption output to message */
			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				qsctest_print_safe("Failure! rcs512_stress_test: decryption failure -RS3 \n");
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

#if defined(QSCTEST_RCS_WIDE_BLOCK_TESTS)
bool qsctest_rcs_wide_equality()
{
	const size_t SMPMIN = 16 * 128;
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_RCS256_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0 };
	uint8_t ncopy[QSC_RCS_NONCE_SIZE] = { 0 };
	qsc_rcs_state ctx1;
	qsc_rcs_state ctx2;
	size_t mctr;
	size_t moft;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	bool status;

	tctr = 0;
	status = true;

	while (tctr < QSCTEST_RCS_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen < SMPMIN);

		dec = (uint8_t*)malloc(mlen);
#if defined(QSC_RCS_AUTHENTICATED)
		enc = (uint8_t*)malloc(mlen + QSC_RCS256_MAC_SIZE);
#else
		enc = (uint8_t*)malloc(mlen);
#endif
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
#if defined(QSC_RCS_AUTHENTICATED)
			qsc_intutils_clear8(enc, mlen + QSC_RCS256_MAC_SIZE);
#else
			qsc_intutils_clear8(enc, mlen);
#endif
			qsc_intutils_clear8(msg, mlen);

			/* generate the key and nonce */
			qsc_csp_generate(key, sizeof(key));
			qsc_csp_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			/* initialize the key parameters struct */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rcs_keyparams kp1 = { key, sizeof(key), nonce };

			/* initialize the state */
			qsc_rcs_initialize(&ctx1, &kp1, true);

			/* encrypt the array */
			qsc_rcs_transform(&ctx1, enc, msg, mlen);

			/* erase the internal state */
			qsc_rcs_dispose(&ctx1);

			/* reset the nonce */
			memcpy(nonce, ncopy, sizeof(nonce));
			qsc_rcs_keyparams kp2 = { key, sizeof(key), nonce };

			/* initialize the state */
			qsc_rcs_initialize(&ctx2, &kp2, false);

			/* encrypt using 16-byte blocks, bypassing AVX512 */

			mctr = mlen;
			moft = 0;

			while (mctr != 0)
			{
				const size_t BLKRMD = qsc_intutils_min(QSC_RCS_BLOCK_SIZE, mctr);
				qsc_rcs_transform(&ctx2, (uint8_t*)(dec + moft), (uint8_t*)(enc + moft), BLKRMD);
				mctr -= BLKRMD;
				moft += BLKRMD;
			}

			/* erase the internal state */
			qsc_rcs_dispose(&ctx2);

			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
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
#endif

void qsctest_rcs_run()
{
	if (qsctest_rcs256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the RCS-256 known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RCS-256 known answer tests. \n");
	}

	if (qsctest_rcs512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the RCS-512 known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RCS-512 known answer tests. \n");
	}

	if (qsctest_rcs256_stress_test() == true)
	{
		qsctest_print_safe("Success! Passed the RCS-256 stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RCS-256 stress test. \n");
	}

	if (qsctest_rcs512_stress_test() == true)
	{
		qsctest_print_safe("Success! Passed the RCS-512 stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RCS-512 stress test. \n");
	}

#if defined(QSCTEST_RCS_WIDE_BLOCK_TESTS)
	if (qsctest_rcs_wide_equality() == true)
	{
		qsctest_print_safe("Success! Passed the RCS AVX-512 equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the RCS AVX-512 equality test. \n");
	}
#endif
}