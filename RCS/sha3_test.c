#include "sha3_test.h"
#include "testutils.h"
#include "intutils.h"
#include "sha3.h"

bool qsctest_sha3_256_kat()
{
	uint8_t exp0[QSC_SHA3_256_HASH_SIZE] = { 0 };
	uint8_t exp24[QSC_SHA3_256_HASH_SIZE] = { 0 };
	uint8_t exp448[QSC_SHA3_256_HASH_SIZE] = { 0 };
	uint8_t exp1600[QSC_SHA3_256_HASH_SIZE] = { 0 };
	uint8_t hash[200] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg24[3] = { 0 };
	uint8_t msg448[56] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t output[QSC_SHA3_256_HASH_SIZE] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsctest_hex_to_bin("A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A", exp0, sizeof(exp0));
	qsctest_hex_to_bin("3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532", exp24, sizeof(exp24));
	qsctest_hex_to_bin("41C0DBA2A9D6240849100376A8235E2C82E1B9998A999E21DB32DD97496D3376", exp448, sizeof(exp448));
	qsctest_hex_to_bin("79F38ADEC5C20307A98EF76E8324AFBFD46CFD81B22E3973C65FA1BD9DE31787", exp1600, sizeof(exp1600));

	qsctest_hex_to_bin("616263", msg24, sizeof(msg24));
	qsctest_hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg448, sizeof(msg448));
	qsctest_hex_to_bin("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute256(output, msg0, 0);

	if (qsc_intutils_are_equal8(output, exp0, sizeof(exp0)) == false)
	{
		qsctest_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute256(output, msg24, sizeof(msg24));

	if (qsc_intutils_are_equal8(output, exp24, sizeof(exp24)) == false)
	{
		qsctest_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK2 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute256(output, msg448, sizeof(msg448));

	if (qsc_intutils_are_equal8(output, exp448, sizeof(exp448)) == false)
	{
		qsctest_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK3 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute256(output, msg1600, sizeof(msg1600));

	if (qsc_intutils_are_equal8(output, exp1600, sizeof(exp1600)) == false)
	{
		qsctest_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK4 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(hash, sizeof(hash));
	/* initialize the SHA3 state structure */
	qsc_sha3_initialize(&state);
	qsc_sha3_update(&state, qsc_keccak_rate_256, msg0, 0);
	qsc_sha3_finalize(&state, qsc_keccak_rate_256, hash);

	if (qsc_intutils_are_equal8(hash, exp0, sizeof(exp0)) == false)
	{
		qsctest_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK5 \n");
		status = false;
	}

	qsc_intutils_clear8(hash, sizeof(hash));
	qsc_sha3_initialize(&state);
	qsc_sha3_update(&state, qsc_keccak_rate_256, msg24, sizeof(msg24));
	qsc_sha3_finalize(&state, qsc_keccak_rate_256, hash);

	if (qsc_intutils_are_equal8(hash, exp24, sizeof(exp24)) == false)
	{
		qsctest_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK6 \n");
		status = false;
	}

	qsc_intutils_clear8(hash, sizeof(hash));
	qsc_sha3_initialize(&state);
	/* absorb the message */
	qsc_sha3_update(&state, qsc_keccak_rate_256, msg448, sizeof(msg448));
	qsc_sha3_finalize(&state, qsc_keccak_rate_256, hash);

	if (qsc_intutils_are_equal8(hash, exp448, sizeof(exp448)) == false)
	{
		qsctest_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK7 \n");
		status = false;
	}

	qsc_intutils_clear8(hash, sizeof(hash));
	/* initialize the SHA3 state structure */
	qsc_sha3_initialize(&state);
	/* absorb the message */
	qsc_sha3_update(&state, qsc_keccak_rate_256, msg1600, sizeof(msg1600));
	/* finalize the message */
	qsc_sha3_finalize(&state, qsc_keccak_rate_256, hash);

	if (qsc_intutils_are_equal8(hash, exp1600, sizeof(exp1600)) == false)
	{
		qsctest_print_safe("Failure! sha3_256_kat: output does not match the known answer -SK8 \n");
		status = false;
	}

	return status;
}

bool qsctest_sha3_512_kat()
{
	uint8_t exp0[QSC_SHA3_512_HASH_SIZE] = { 0 };
	uint8_t exp24[QSC_SHA3_512_HASH_SIZE] = { 0 };
	uint8_t exp448[QSC_SHA3_512_HASH_SIZE] = { 0 };
	uint8_t exp1600[QSC_SHA3_512_HASH_SIZE] = { 0 };
	uint8_t hash[200] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg24[3] = { 0 };
	uint8_t msg448[56] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t output[QSC_SHA3_512_HASH_SIZE] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsctest_hex_to_bin("A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A6"
		"15B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26", exp0, sizeof(exp0));
	qsctest_hex_to_bin("B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E"
		"10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0", exp24, sizeof(exp24));
	qsctest_hex_to_bin("04A371E84ECFB5B8B77CB48610FCA8182DD457CE6F326A0FD3D7EC2F1E91636D"
		"EE691FBE0C985302BA1B0D8DC78C086346B533B49C030D99A27DAF1139D6E75E", exp448, sizeof(exp448));
	qsctest_hex_to_bin("E76DFAD22084A8B1467FCF2FFA58361BEC7628EDF5F3FDC0E4805DC48CAEECA8"
		"1B7C13C30ADF52A3659584739A2DF46BE589C51CA1A4A8416DF6545A1CE8BA00", exp1600, sizeof(exp1600));

	qsctest_hex_to_bin("616263", msg24, sizeof(msg24));
	qsctest_hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg448, sizeof(msg448));
	qsctest_hex_to_bin("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute512(output, msg0, 0);

	if (qsc_intutils_are_equal8(output, exp0, sizeof(exp0)) == false)
	{
		qsctest_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute512(output, msg24, sizeof(msg24));

	if (qsc_intutils_are_equal8(output, exp24, sizeof(exp24)) == false)
	{
		qsctest_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK2 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute512(output, msg448, sizeof(msg448));

	if (qsc_intutils_are_equal8(output, exp448, sizeof(exp448)) == false)
	{
		qsctest_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK3 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_sha3_compute512(output, msg1600, sizeof(msg1600));

	if (qsc_intutils_are_equal8(output, exp1600, sizeof(exp1600)) == false)
	{
		qsctest_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK4 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(hash, sizeof(hash));
	/* initialize the SHA3 state structure */
	qsc_sha3_initialize(&state);
	qsc_sha3_update(&state, qsc_keccak_rate_512, msg0, 0);
	qsc_sha3_finalize(&state, qsc_keccak_rate_512, hash);

	if (qsc_intutils_are_equal8(hash, exp0, sizeof(exp0)) == false)
	{
		qsctest_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK5 \n");
		status = false;
	}

	qsc_intutils_clear8(hash, sizeof(hash));
	qsc_sha3_initialize(&state);
	qsc_sha3_update(&state, qsc_keccak_rate_512, msg24, sizeof(msg24));
	qsc_sha3_finalize(&state, qsc_keccak_rate_512, hash);

	if (qsc_intutils_are_equal8(hash, exp24, sizeof(exp24)) == false)
	{
		qsctest_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK6 \n");
		status = false;
	}

	qsc_intutils_clear8(hash, sizeof(hash));
	qsc_sha3_initialize(&state);
	qsc_sha3_update(&state, qsc_keccak_rate_512, msg448, sizeof(msg448));
	qsc_sha3_finalize(&state, qsc_keccak_rate_512, hash);

	if (qsc_intutils_are_equal8(hash, exp448, sizeof(exp448)) == false)
	{
		qsctest_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK7 \n");
		status = false;
	}

	qsc_intutils_clear8(hash, sizeof(hash));
	/* initialize the SHA3 state*/
	qsc_sha3_initialize(&state);
	/* absorb the message */
	qsc_sha3_update(&state, qsc_keccak_rate_512, msg1600, sizeof(msg1600));
	/* finalize the message */
	qsc_sha3_finalize(&state, qsc_keccak_rate_512, hash);

	if (qsc_intutils_are_equal8(hash, exp1600, sizeof(exp1600)) == false)
	{
		qsctest_print_safe("Failure! sha3_512_kat: output does not match the known answer -SK8 \n");
		status = false;
	}

	return status;
}

bool qsctest_shake_128_kat()
{
	uint8_t exp0[512] = { 0 };
	uint8_t exp1600[512] = { 0 };
	uint8_t hash[qsc_keccak_rate_128 * 4] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t output[512] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsctest_hex_to_bin("7F9C2BA4E88F827D616045507605853ED73B8093F6EFBC88EB1A6EACFA66EF26"
		"3CB1EEA988004B93103CFB0AEEFD2A686E01FA4A58E8A3639CA8A1E3F9AE57E2"
		"35B8CC873C23DC62B8D260169AFA2F75AB916A58D974918835D25E6A435085B2"
		"BADFD6DFAAC359A5EFBB7BCC4B59D538DF9A04302E10C8BC1CBF1A0B3A5120EA"
		"17CDA7CFAD765F5623474D368CCCA8AF0007CD9F5E4C849F167A580B14AABDEF"
		"AEE7EEF47CB0FCA9767BE1FDA69419DFB927E9DF07348B196691ABAEB580B32D"
		"EF58538B8D23F87732EA63B02B4FA0F4873360E2841928CD60DD4CEE8CC0D4C9"
		"22A96188D032675C8AC850933C7AFF1533B94C834ADBB69C6115BAD4692D8619"
		"F90B0CDF8A7B9C264029AC185B70B83F2801F2F4B3F70C593EA3AEEB613A7F1B"
		"1DE33FD75081F592305F2E4526EDC09631B10958F464D889F31BA010250FDA7F"
		"1368EC2967FC84EF2AE9AFF268E0B1700AFFC6820B523A3D917135F2DFF2EE06"
		"BFE72B3124721D4A26C04E53A75E30E73A7A9C4A95D91C55D495E9F51DD0B5E9"
		"D83C6D5E8CE803AA62B8D654DB53D09B8DCFF273CDFEB573FAD8BCD45578BEC2"
		"E770D01EFDE86E721A3F7C6CCE275DABE6E2143F1AF18DA7EFDDC4C7B70B5E34"
		"5DB93CC936BEA323491CCB38A388F546A9FF00DD4E1300B9B2153D2041D205B4"
		"43E41B45A653F2A5C4492C1ADD544512DDA2529833462B71A41A45BE97290B6F", exp0, sizeof(exp0));

	qsctest_hex_to_bin("131AB8D2B594946B9C81333F9BB6E0CE75C3B93104FA3469D3917457385DA037"
		"CF232EF7164A6D1EB448C8908186AD852D3F85A5CF28DA1AB6FE343817197846"
		"7F1C05D58C7EF38C284C41F6C2221A76F12AB1C04082660250802294FB871802"
		"13FDEF5B0ECB7DF50CA1F8555BE14D32E10F6EDCDE892C09424B29F597AFC270"
		"C904556BFCB47A7D40778D390923642B3CBD0579E60908D5A000C1D08B98EF93"
		"3F806445BF87F8B009BA9E94F7266122ED7AC24E5E266C42A82FA1BBEFB7B8DB"
		"0066E16A85E0493F07DF4809AEC084A593748AC3DDE5A6D7AAE1E8B6E5352B2D"
		"71EFBB47D4CAEED5E6D633805D2D323E6FD81B4684B93A2677D45E7421C2C6AE"
		"A259B855A698FD7D13477A1FE53E5A4A6197DBEC5CE95F505B520BCD9570C4A8"
		"265A7E01F89C0C002C59BFEC6CD4A5C109258953EE5EE70CD577EE217AF21FA7"
		"0178F0946C9BF6CA8751793479F6B537737E40B6ED28511D8A2D7E73EB75F8DA"
		"AC912FF906E0AB955B083BAC45A8E5E9B744C8506F37E9B4E749A184B30F43EB"
		"188D855F1B70D71FF3E50C537AC1B0F8974F0FE1A6AD295BA42F6AEC74D123A7"
		"ABEDDE6E2C0711CAB36BE5ACB1A5A11A4B1DB08BA6982EFCCD716929A7741CFC"
		"63AA4435E0B69A9063E880795C3DC5EF3272E11C497A91ACF699FEFEE206227A"
		"44C9FB359FD56AC0A9A75A743CFF6862F17D7259AB075216C0699511643B6439", exp1600, sizeof(exp1600));

	qsctest_hex_to_bin("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_shake128_compute(output, sizeof(output), msg0, 0);

	if (qsc_intutils_are_equal8(output, exp0, sizeof(exp0)) == false)
	{
		qsctest_print_safe("Failure! shake_128_kat: output does not match the known answer -DK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_shake128_compute(output, sizeof(output), msg1600, sizeof(msg1600));

	if (qsc_intutils_are_equal8(output, exp1600, sizeof(exp1600)) == false)
	{
		qsctest_print_safe("Failure! shake_128_kat: output does not match the known answer -DK2 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(hash, sizeof(hash));
	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_shake_initialize(&state, qsc_keccak_rate_128, msg1600, sizeof(msg1600));
	qsc_shake_squeezeblocks(&state, qsc_keccak_rate_128, hash, 4);

	if (qsc_intutils_are_equal8(hash, exp1600, sizeof(exp1600)) == false)
	{
		qsctest_print_safe("Failure! shake_128_kat: output does not match the known answer -DK3 \n");
		status = false;
	}

	return status;
}

bool qsctest_shake_256_kat()
{
	uint8_t exp0[512] = { 0 };
	uint8_t exp1600[512] = { 0 };
	uint8_t hash[qsc_keccak_rate_256 * 4] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t output[512] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsctest_hex_to_bin("46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762F"
		"D75DC4DDD8C0F200CB05019D67B592F6FC821C49479AB48640292EACB3B7C4BE"
		"141E96616FB13957692CC7EDD0B45AE3DC07223C8E92937BEF84BC0EAB862853"
		"349EC75546F58FB7C2775C38462C5010D846C185C15111E595522A6BCD16CF86"
		"F3D122109E3B1FDD943B6AEC468A2D621A7C06C6A957C62B54DAFC3BE87567D6"
		"77231395F6147293B68CEAB7A9E0C58D864E8EFDE4E1B9A46CBE854713672F5C"
		"AAAE314ED9083DAB4B099F8E300F01B8650F1F4B1D8FCF3F3CB53FB8E9EB2EA2"
		"03BDC970F50AE55428A91F7F53AC266B28419C3778A15FD248D339EDE785FB7F"
		"5A1AAA96D313EACC890936C173CDCD0FAB882C45755FEB3AED96D477FF96390B"
		"F9A66D1368B208E21F7C10D04A3DBD4E360633E5DB4B602601C14CEA737DB3DC"
		"F722632CC77851CBDDE2AAF0A33A07B373445DF490CC8FC1E4160FF118378F11"
		"F0477DE055A81A9EDA57A4A2CFB0C83929D310912F729EC6CFA36C6AC6A75837"
		"143045D791CC85EFF5B21932F23861BCF23A52B5DA67EAF7BAAE0F5FB1369DB7"
		"8F3AC45F8C4AC5671D85735CDDDB09D2B1E34A1FC066FF4A162CB263D6541274"
		"AE2FCC865F618ABE27C124CD8B074CCD516301B91875824D09958F341EF274BD"
		"AB0BAE316339894304E35877B0C28A9B1FD166C796B9CC258A064A8F57E27F2A", exp0, sizeof(exp0));

	qsctest_hex_to_bin("CD8A920ED141AA0407A22D59288652E9D9F1A7EE0C1E7C1CA699424DA84A904D"
		"2D700CAAE7396ECE96604440577DA4F3AA22AEB8857F961C4CD8E06F0AE6610B"
		"1048A7F64E1074CD629E85AD7566048EFC4FB500B486A3309A8F26724C0ED628"
		"001A1099422468DE726F1061D99EB9E93604D5AA7467D4B1BD6484582A384317"
		"D7F47D750B8F5499512BB85A226C4243556E696F6BD072C5AA2D9B69730244B5"
		"6853D16970AD817E213E470618178001C9FB56C54FEFA5FEE67D2DA524BB3B0B"
		"61EF0E9114A92CDBB6CCCB98615CFE76E3510DD88D1CC28FF99287512F24BFAF"
		"A1A76877B6F37198E3A641C68A7C42D45FA7ACC10DAE5F3CEFB7B735F12D4E58"
		"9F7A456E78C0F5E4C4471FFFA5E4FA0514AE974D8C2648513B5DB494CEA84715"
		"6D277AD0E141C24C7839064CD08851BC2E7CA109FD4E251C35BB0A04FB05B364"
		"FF8C4D8B59BC303E25328C09A882E952518E1A8AE0FF265D61C465896973D749"
		"0499DC639FB8502B39456791B1B6EC5BCC5D9AC36A6DF622A070D43FED781F5F"
		"149F7B62675E7D1A4D6DEC48C1C7164586EAE06A51208C0B791244D307726505"
		"C3AD4B26B6822377257AA152037560A739714A3CA79BD605547C9B78DD1F596F"
		"2D4F1791BC689A0E9B799A37339C04275733740143EF5D2B58B96A363D4E0807"
		"6A1A9D7846436E4DCA5728B6F760EEF0CA92BF0BE5615E96959D767197A0BEEB", exp1600, sizeof(exp1600));

	qsctest_hex_to_bin("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_shake256_compute(output, sizeof(output), msg0, 0);

	if (qsc_intutils_are_equal8(output, exp0, sizeof(exp0)) == false)
	{
		qsctest_print_safe("Failure! shake_256_kat: output does not match the known answer -DK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_shake256_compute(output, sizeof(output), msg1600, sizeof(msg1600));

	if (qsc_intutils_are_equal8(output, exp1600, sizeof(exp1600)) == false)
	{
		qsctest_print_safe("Failure! shake_256_kat: output does not match the known answer -DK2 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(hash, sizeof(hash));
	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_shake_initialize(&state, qsc_keccak_rate_256, msg1600, sizeof(msg1600));
	qsc_cshake_squeezeblocks(&state, qsc_keccak_rate_256, hash, 4);

	if (qsc_intutils_are_equal8(hash, exp1600, sizeof(exp1600)) == false)
	{
		qsctest_print_safe("Failure! shake_256_kat: output does not match the known answer -DK3 \n");
		status = false;
	}

	return status;
}

bool qsctest_shake_512_kat()
{
	uint8_t exp1[512] = { 0 };
	uint8_t exp2[512] = { 0 };
	uint8_t hash[qsc_keccak_rate_512 * 8] = { 0 };
	uint8_t msg1[64] = { 0 };
	uint8_t msg2[200] = { 0 };
	uint8_t output[512] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsctest_hex_to_bin("D6DEAAF94A391E987698B17E0AE2D8C6C96BEAC5DD2FFCB20F45665EFE39CFFE"
		"7ED119E38899BD3E8FD206A1A77B74F435D405BB837E61A62D97D5BAA203300A"
		"E689BA5F3B6659355964FED145065B3B0371C6CA4E466942B81BBD47CB2AE373"
		"8D630EFC00CBBBC0B11FF56C6AD16E1500980D94112F039003F9F36A3D05567B"
		"A3810BA76EC6E5893E3B2A0CBAFA9EEE123ED1BB64AA7AD4DD21A540EA14810D"
		"73611D6C1852A9726445199856CD52C054FBB92EE8A0BF83FB6BFCA5FA05C290"
		"AC2F58868140A07E23EE1634097E0414661352CAA4E4EDC88BF0D00AC6022C49"
		"A3AB60B1393C3FB56E668FD504C8D74F747E1C84DEB34C5560F5A421CB3F87CC"
		"741A380403378E7C7BE009724149FAB8F95BCBA485D7F45303E9DBF0B4596F60"
		"731FCF11DD90112670572964F2CFA72168212B41A640140253E55C09043CAEE3"
		"96C461B0B8C386329710BB0C562963D3C919A20A5BFA7310271319CB086C12F6"
		"7F62C4F6BECB52F8953688CE215436D53A0516F31C994AF16C121297385B6D83"
		"94875A3FB64A5CD9BC2004F319D358C37302E2524736F32DAEE5F2F09D6DFCC1"
		"1FCAE121536A1428D79F246E1FEFED8619E652BC1BA0CA8D840E624F5245E7CB"
		"F2A15CAA8880653B3746807CB83F52A6B2FBCFBA9E708702F5A8E68D79FCE865"
		"898CB646F40CC3CBAC51CC94729EDFD1754298B3AAEAE94D090240A7BBFE3FBA", exp1, sizeof(exp1));

	qsctest_hex_to_bin("9701303D390F51968C25B6EEE54816D19AB149A1C06B0625940BB8E04A1CECCD"
		"D88010234F53ABBBAF181F49761A3ECEFAEE56DE7B59B5AAF0031E3C1552C9AC"
		"40DFAF6AAC934FD644DBC4A3D753E1F3845A5901F415DFF2A88440F6A8F5688F"
		"F26E68ECC6AD23ACF18E0A54BE745DB919FAB01F77A251D5F66B01E2426BF020"
		"BC27A6DFF274DC987313A42F1AC159F481A46F5BFB53914C7E79191F491C7808"
		"DE0EDF3BCA24FD7DFD713806C062326C16FFAC00D1F8E94BA2DA0DE06D5F1826"
		"A5AE881313AAD40FD0F260822ABB83ACC72E86006B1B04C28A0A30EAEB39040E"
		"BD0D4ADB76263BD1186464A5CBA30B4332C1ACC5328B989A998B5F5CA5184AE6"
		"DDAD039A3117C05C9CB2EA4DF5F8A2E8BD945EE42CE1789CE568D2BD7263DDF5"
		"6520D040BB406AD2D10DE2E3714D049381737CEA1AE05062650AFCE1B1DE1F77"
		"B418C7F7C4B1A5C233EF78FFC1D67215BEFDDCFA8E4C1CA64FF547B21DE12E20"
		"11D8214D0BBAB6645ED240313C4D86646BEC8F9D58B788227B535BFCB8B75448"
		"94E4A4BCD6DA9BF182DCEDD60348BD62579C898DBA9A6B6AA9E87E9C29F5855F"
		"57F138ACA68EB7B89DBE7DD09B217E94C4E57974E96A28868202D643F08DF096"
		"21AE714C2B47365DC44F608B97B5C5E0791EBE3C245CCCC1B537030EEDAA096F"
		"EF24013B7D401C9C7470375D97A6A26066CFB7B88E72F6D6B635E9F09DB2C007", exp2, sizeof(exp2));

	qsctest_hex_to_bin("9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10"
		"9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10", msg1, sizeof(msg1));

	qsctest_hex_to_bin("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
		"A3A3A3A3A3A3A3A3", msg2, sizeof(msg2));

	status = true;

	/* test compact api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_shake512_compute(output, sizeof(output), msg1, sizeof(msg1));

	if (qsc_intutils_are_equal8(output, exp1, sizeof(exp1)) == false)
	{
		qsctest_print_safe("Failure! shake_512_kat: output does not match the known answer -DK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_shake512_compute(output, sizeof(output), msg2, sizeof(msg2));

	if (qsc_intutils_are_equal8(output, exp2, sizeof(exp2)) == false)
	{
		qsctest_print_safe("Failure! shake_512_kat: output does not match the known answer -DK2 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_shake_initialize(&state, qsc_keccak_rate_512, msg1, sizeof(msg1));
	qsc_shake_squeezeblocks(&state, qsc_keccak_rate_512, hash, 8);

	if (qsc_intutils_are_equal8(hash, exp1, sizeof(exp1)) == false)
	{
		qsctest_print_safe("Failure! shake_512_kat: output does not match the known answer -DK3 \n");
		status = false;
	}

	return status;
}

bool qsctest_cshake_128_kat()
{
	uint8_t cust[15] = { 0 };
	uint8_t exp256a[32] = { 0 };
	uint8_t exp256b[32] = { 0 };
	uint8_t hashb[qsc_keccak_rate_128] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t name[1] = { 0 };
	uint8_t output[32] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsctest_hex_to_bin("456D61696C205369676E6174757265", cust, sizeof(cust));

	qsctest_hex_to_bin("C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5", exp256a, sizeof(exp256a));
	qsctest_hex_to_bin("C5221D50E4F822D96A2E8881A961420F294B7B24FE3D2094BAED2C6524CC166B", exp256b, sizeof(exp256b));

	qsctest_hex_to_bin("00010203", msg32, sizeof(msg32));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_cshake128_compute(output, sizeof(output), msg32, sizeof(msg32), name, 0, cust, sizeof(cust));

	if (qsc_intutils_are_equal8(output, exp256a, sizeof(exp256a)) == false)
	{
		qsctest_print_safe("Failure! cshake_128_kat: output does not match the known answer -CK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_cshake128_compute(output, sizeof(output), msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));

	if (qsc_intutils_are_equal8(output, exp256b, sizeof(exp256b)) == false)
	{
		qsctest_print_safe("Failure! cshake_128_kat: output does not match the known answer -CK2 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_cshake_initialize(&state, qsc_keccak_rate_128, msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));
	qsc_cshake_squeezeblocks(&state, qsc_keccak_rate_128, hashb, 1);

	if (qsc_intutils_are_equal8(hashb, exp256b, sizeof(exp256b)) == false)
	{
		qsctest_print_safe("Failure! cshake_128_kat: output does not match the known answer -CK3 \n");
		status = false;
	}

	return status;
}

bool qsctest_cshake_256_kat()
{
	uint8_t cust[15] = { 0 };
	uint8_t exp512a[64] = { 0 };
	uint8_t exp512b[64] = { 0 };
	uint8_t hashb[qsc_keccak_rate_256] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t name[1] = { 0 };
	uint8_t output[64] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsctest_hex_to_bin("456D61696C205369676E6174757265", cust, sizeof(cust));

	qsctest_hex_to_bin("D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD1"
		"64020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C", exp512a, sizeof(exp512a));
	qsctest_hex_to_bin("07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC864302730917"
		"27F42B17ED1DF63E8EC118F04B23633C1DFB1574C8FB55CB45DA8E25AFB092BB", exp512b, sizeof(exp512b));

	qsctest_hex_to_bin("00010203", msg32, sizeof(msg32));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_cshake256_compute(output, sizeof(output), msg32, sizeof(msg32), name, 0, cust, sizeof(cust));

	if (qsc_intutils_are_equal8(output, exp512a, sizeof(exp512a)) == false)
	{
		qsctest_print_safe("Failure! cshake_256_kat: output does not match the known answer -CK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_cshake256_compute(output, sizeof(output), msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));

	if (qsc_intutils_are_equal8(output, exp512b, sizeof(exp512b)) == false)
	{
		qsctest_print_safe("Failure! cshake_256_kat: output does not match the known answer -CK2 \n");
		status = false;
	}

	/* test long-form api */


	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_cshake_initialize(&state, qsc_keccak_rate_256, msg1600, sizeof(msg1600), name, 0, cust, sizeof(cust));
	qsc_cshake_squeezeblocks(&state, qsc_keccak_rate_256, hashb, 1);

	if (qsc_intutils_are_equal8(hashb, exp512b, sizeof(exp512b)) == false)
	{
		qsctest_print_safe("Failure! cshake_256_kat: output does not match the known answer -CK3 \n");
		status = false;
	}

	return status;
}

bool qsctest_cshake_512_kat()
{
	uint8_t exp512[64] = { 0 };
	uint8_t cust[15] = { 0 };
	uint8_t hashb[qsc_keccak_rate_512] = { 0 };
	uint8_t msg512[64] = { 0 };
	uint8_t output[64] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsctest_hex_to_bin("456D61696C205369676E6174757265", cust, sizeof(cust));

	qsctest_hex_to_bin("EF4BDC1F2B91B44C51048C81F5499DAC46F38C6E9CD81CEA3CB85E3A1913F8C4"
		"54CFE40F05370F7DE24E50FC49BBD188F42D2439F25DC2B3DB7CA2E38DC7E4A6", exp512, sizeof(exp512));

	qsctest_hex_to_bin("9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10"
		"9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10", msg512, sizeof(msg512));

	status = true;

	/* test compact api */

	qsc_cshake512_compute(output, sizeof(output), msg512, sizeof(msg512), NULL, 0, cust, sizeof(cust));

	if (qsc_intutils_are_equal8(output, exp512, sizeof(exp512)) == false)
	{
		qsctest_print_safe("Failure! cshake_512_kat: output does not match the known answer -CK1 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear8(output, sizeof(output));
	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);

	qsc_cshake_initialize(&state, qsc_keccak_rate_512, msg512, sizeof(msg512), NULL, 0, cust, sizeof(cust));
	qsc_cshake_squeezeblocks(&state, qsc_keccak_rate_512, hashb, 1);

	if (qsc_intutils_are_equal8(hashb, exp512, sizeof(exp512)) == false)
	{
		qsctest_print_safe("Failure! cshake_512_kat: output does not match the known answer -CK2 \n");
		status = false;
	}

	return status;
}

bool qsctest_kmac_128_kat()
{
	uint8_t cust0[1] = { 0 };
	uint8_t cust168[21] = { 0 };
	uint8_t exp256a[32] = { 0 };
	uint8_t exp256b[32] = { 0 };
	uint8_t exp256c[32] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t key256[32] = { 0 };
	uint8_t output[32] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust168, sizeof(cust168));
	qsctest_hex_to_bin("E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E", exp256a, sizeof(exp256a));
	qsctest_hex_to_bin("3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5", exp256b, sizeof(exp256b));
	qsctest_hex_to_bin("1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230", exp256c, sizeof(exp256c));
	qsctest_hex_to_bin("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", key256, sizeof(key256));
	qsctest_hex_to_bin("00010203", msg32, sizeof(msg32));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_kmac128_compute(output, sizeof(output), msg32, sizeof(msg32), key256, sizeof(key256), cust0, 0);

	if (qsc_intutils_are_equal8(output, exp256a, sizeof(exp256a)) == false)
	{
		qsctest_print_safe("Failure! kmac_128_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kmac128_compute(output, sizeof(output), msg32, sizeof(msg32), key256, sizeof(key256), cust168, sizeof(cust168));

	if (qsc_intutils_are_equal8(output, exp256b, sizeof(exp256b)) == false)
	{
		qsctest_print_safe("Failure! kmac_128_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kmac128_compute(output, sizeof(output), msg1600, sizeof(msg1600), key256, sizeof(key256), cust168, sizeof(cust168));

	if (qsc_intutils_are_equal8(output, exp256c, sizeof(exp256c)) == false)
	{
		qsctest_print_safe("Failure! kmac_128_kat: output does not match the known answer -KK3 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_intutils_clear8(output, sizeof(output));

	qsc_kmac_initialize(&state, qsc_keccak_rate_128, key256, sizeof(key256), cust168, sizeof(cust168));
	qsc_kmac_update(&state, qsc_keccak_rate_128, msg1600, sizeof(msg1600));
	qsc_kmac_finalize(&state, qsc_keccak_rate_128, output, sizeof(output));

	if (qsc_intutils_are_equal8(output, exp256c, sizeof(exp256c)) == false)
	{
		qsctest_print_safe("Failure! kmac_128_kat: output does not match the known answer -KK4 \n");
		status = false;
	}

	return status;
}

bool qsctest_kmac_256_kat()
{
	uint8_t cust0[1] = { 0 };
	uint8_t cust168[21] = { 0 };
	uint8_t exp256a[64] = { 0 };
	uint8_t exp256b[64] = { 0 };
	uint8_t exp256c[64] = { 0 };
	uint8_t msg32[4] = { 0 };
	uint8_t msg1600[200] = { 0 };
	uint8_t key256[32] = { 0 };
	uint8_t output[64] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust168, sizeof(cust168));

	qsctest_hex_to_bin("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7"
		"F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD", exp256a, sizeof(exp256a));
	qsctest_hex_to_bin("75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691"
		"589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69", exp256b, sizeof(exp256b));
	qsctest_hex_to_bin("B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D9"
		"70FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965", exp256c, sizeof(exp256c));

	qsctest_hex_to_bin("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F", key256, sizeof(key256));

	qsctest_hex_to_bin("00010203", msg32, sizeof(msg32));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7", msg1600, sizeof(msg1600));

	status = true;

	/* test compact api */

	qsc_kmac256_compute(output, sizeof(output), msg32, sizeof(msg32), key256, sizeof(key256), cust168, sizeof(cust168));

	if (qsc_intutils_are_equal8(output, exp256a, sizeof(exp256a)) == false)
	{
		qsctest_print_safe("Failure! kmac_256_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kmac256_compute(output, sizeof(output), msg1600, sizeof(msg1600), key256, sizeof(key256), cust0, 0);

	if (qsc_intutils_are_equal8(output, exp256b, sizeof(exp256b)) == false)
	{
		qsctest_print_safe("Failure! kmac_256_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kmac256_compute(output, sizeof(output), msg1600, sizeof(msg1600), key256, sizeof(key256), cust168, sizeof(cust168));

	if (qsc_intutils_are_equal8(output, exp256c, sizeof(exp256c)) == false)
	{
		qsctest_print_safe("Failure! kmac_256_kat: output does not match the known answer -KK3 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_intutils_clear8(output, sizeof(output));

	qsc_kmac_initialize(&state, qsc_keccak_rate_256, key256, sizeof(key256), cust168, sizeof(cust168));
	qsc_kmac_update(&state, qsc_keccak_rate_256, msg1600, sizeof(msg1600));
	qsc_kmac_finalize(&state, qsc_keccak_rate_256, output, sizeof(output));

	if (qsc_intutils_are_equal8(output, exp256c, sizeof(exp256c)) == false)
	{
		qsctest_print_safe("Failure! kmac_256_kat: output does not match the known answer -KK4 \n");
		status = false;
	}

	return status;
}

bool qsctest_kmac_512_kat()
{
	uint8_t cust0[21] = { 0 };
	uint8_t cust1[42] = { 0 };
	uint8_t cust2[45] = { 0 };
	uint8_t exp0[64] = { 0 };
	uint8_t exp1[64] = { 0 };
	uint8_t exp2[64] = { 0 };
	uint8_t key0[21] = { 0 };
	uint8_t key1[60] = { 0 };
	uint8_t msg0[42] = { 0 };
	uint8_t msg1[84] = { 0 };
	uint8_t output[64] = { 0 };
	qsc_keccak_state state;
	bool status;

	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust0, sizeof(cust0));
	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E", cust1, sizeof(cust1));
	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E4D7920", cust2, sizeof(cust2));

	qsctest_hex_to_bin("C41F31CEE9851BAA915716C16F7670C7C137C1908BD9694DA80C679AA6EB5964"
		"E76AD91F2018DE576524D84E0B0FC586C06B110ED6DB273A921FFC86D1C20CE8", exp0, sizeof(exp0));
	qsctest_hex_to_bin("6535FB96EAB4F831D801E6C3C6E71755F4A56E8E711D376DDC564F5C6DACB8B5"
		"91EEF0503F433872B401FCEF8F05DA42FB950176C10FDB59395273FB9EDA39B8", exp1, sizeof(exp1));
	qsctest_hex_to_bin("7BA4F7EE765960E6DA15D2CB51775DBA3E7B9279E5740469EF9FFD04C5246091"
		"9A99BEE5BFDA27163E2729A8E3B663BD963EF067C7CCABDE6F6EFFF9093E2A2F", exp2, sizeof(exp2));

	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E", key0, sizeof(key0));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B", key1, sizeof(key1));

	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E", msg0, sizeof(msg0));
	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041"
		"70706C69636174696F6E4D7920546167676564204170706C69636174696F6E4D"
		"7920546167676564204170706C69636174696F6E", msg1, sizeof(msg1));
	status = true;

	/* test compact api */

	qsc_kmac512_compute(output, sizeof(output), msg0, sizeof(msg0), key0, sizeof(key0), cust0, sizeof(cust0));

	if (qsc_intutils_are_equal8(output, exp0, sizeof(exp0)) == false)
	{
		qsctest_print_safe("Failure! kmac_512_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kmac512_compute(output, sizeof(output), msg0, sizeof(msg0), key1, sizeof(key1), cust2, sizeof(cust2));

	if (qsc_intutils_are_equal8(output, exp1, sizeof(exp1)) == false)
	{
		qsctest_print_safe("Failure! kmac_512_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kmac512_compute(output, sizeof(output), msg1, sizeof(msg1), key0, sizeof(key0), cust1, sizeof(cust1));

	if (qsc_intutils_are_equal8(output, exp2, sizeof(exp2)) == false)
	{
		qsctest_print_safe("Failure! kmac_512_kat: output does not match the known answer -KK3 \n");
		status = false;
	}

	/* test long-form api */

	qsc_intutils_clear64(state.state, QSC_KECCAK_STATE_SIZE);
	qsc_intutils_clear8(output, sizeof(output));

	qsc_kmac_initialize(&state, qsc_keccak_rate_512, key0, sizeof(key0), cust1, sizeof(cust1));
	qsc_kmac_update(&state, qsc_keccak_rate_512, msg1, sizeof(msg1));
	qsc_kmac_finalize(&state, qsc_keccak_rate_512, output, sizeof(output));

	if (qsc_intutils_are_equal8(output, exp2, sizeof(exp2)) == false)
	{
		qsctest_print_safe("Failure! kmac_512_kat: output does not match the known answer -KK4 \n");
		status = false;
	}

	return status;
}

bool qsctest_kpa_256_kat()
{
	uint8_t cust168[21] = { 0 };
	uint8_t exp256a[32] = { 0 };
	uint8_t exp256b[32] = { 0 };
	uint8_t msg256[32] = { 0 };
	uint8_t msg8704[1088] = { 0 };
	uint8_t key256[32] = { 0 };
	uint8_t output[32] = { 0 };
	qsc_kpa_state ctx;
	bool status;

	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust168, sizeof(cust168));
	qsctest_hex_to_bin("EBEC64EBE52DA21D9465341CBDC4941F5141855F8B62312EBDFC015083315193", exp256a, sizeof(exp256a));
	qsctest_hex_to_bin("36DB74619B441167575FCD69E4B4DFDEECFF97F99F49BB68B7EB7A4FDC5A9E20", exp256b, sizeof(exp256b));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", key256, sizeof(key256));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", msg256, sizeof(msg256));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
		"E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
		"E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
		"E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
		"E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", msg8704, sizeof(msg8704));

	status = true;

	qsc_kpa_initialize(&ctx, key256, sizeof(key256), cust168, sizeof(cust168));
	qsc_kpa_update(&ctx, msg8704, sizeof(msg8704));
	qsc_kpa_finalize(&ctx, output, sizeof(output));

	if (qsc_intutils_are_equal8(output, exp256a, sizeof(exp256a)) == false)
	{
		qsctest_print_safe("Failure! kpa_256_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kpa_initialize(&ctx, key256, sizeof(key256), NULL, 0);
	qsc_kpa_update(&ctx, msg256, sizeof(msg256));
	qsc_kpa_finalize(&ctx, output, sizeof(output));

	if (qsc_intutils_are_equal8(output, exp256b, sizeof(exp256b)) == false)
	{
		qsctest_print_safe("Failure! kpa_256_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	return status;
}

bool qsctest_kpa_512_kat()
{
	uint8_t cust168[21] = { 0 };
	uint8_t exp512a[64] = { 0 };
	uint8_t exp512b[64] = { 0 };
	uint8_t msg512[64] = { 0 };
	uint8_t msg4608[576] = { 0 };
	uint8_t key512[64] = { 0 };
	uint8_t output[64] = { 0 };
	qsc_kpa_state ctx;
	bool status;

	qsctest_hex_to_bin("4D7920546167676564204170706C69636174696F6E", cust168, sizeof(cust168));
	qsctest_hex_to_bin("5A3A48CE2221347213A93A847EAEF6455351018E1239C130069DB1A71DCF28DC"
		"8D9FB65193F1AB620752A4FEA0DDF0ED5824CAB50DD37BBC4A8909A91ADBC2C2", exp512a, sizeof(exp512a));
	qsctest_hex_to_bin("D31EDF6ABD9B4497C98F065C398622E51DCC24B96DA9345D613757274472C612"
		"165218DD0F15D86E93894289AD95081FF5CE80FFFAAB5625D3CBFAC4CEB88898", exp512b, sizeof(exp512b));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", key512, sizeof(key512));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", msg512, sizeof(msg512));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
		"E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
		"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
		"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
		"A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
		"C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
		"E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", msg4608, sizeof(msg4608));

	status = true;

	qsc_kpa_initialize(&ctx, key512, sizeof(key512), cust168, sizeof(cust168));
	qsc_kpa_update(&ctx, msg4608, sizeof(msg4608));
	qsc_kpa_finalize(&ctx, output, sizeof(output));

	if (qsc_intutils_are_equal8(output, exp512a, sizeof(exp512a)) == false)
	{
		qsctest_print_safe("Failure! kpa_512_kat: output does not match the known answer -KK1 \n");
		status = false;
	}

	qsc_intutils_clear8(output, sizeof(output));
	qsc_kpa_initialize(&ctx, key512, sizeof(key512), NULL, 0);
	qsc_kpa_update(&ctx, msg512, sizeof(msg512));
	qsc_kpa_finalize(&ctx, output, sizeof(output));

	if (qsc_intutils_are_equal8(output, exp512b, sizeof(exp512b)) == false)
	{
		qsctest_print_safe("Failure! kpa_512_kat: output does not match the known answer -KK2 \n");
		status = false;
	}

	return status;
}

#if defined(QSC_SYSTEM_HAS_AVX2)
bool qsctest_kmac128x4_equality()
{
	uint8_t cst[4][16] = { 0 };
	uint8_t key[4][18] = { 0 };
	uint8_t msg[4][256] = { 0 };
	uint8_t otp[4][16] = { 0 };
	uint8_t exp[4][16] = { 0 };
	size_t i;
	bool status;

	status = true;

	for (i = 0; i < 16; ++i)
	{
		cst[0][i] = (uint8_t)i;
		cst[1][i] = (uint8_t)i;
		cst[2][i] = (uint8_t)i;
		cst[3][i] = (uint8_t)i;
		key[0][i] = (uint8_t)i;
		key[1][i] = (uint8_t)i;
		key[2][i] = (uint8_t)i;
		key[3][i] = (uint8_t)i;
	}

	key[0][16] = (uint8_t)1;
	key[1][16] = (uint8_t)2;
	key[2][16] = (uint8_t)3;
	key[3][16] = (uint8_t)4;

	for (i = 0; i < 256; ++i)
	{
		msg[0][i] = (uint8_t)i;
		msg[1][i] = (uint8_t)i;
		msg[2][i] = (uint8_t)i;
		msg[3][i] = (uint8_t)i;
	}

	qsc_kmac128_compute(exp[0], 16, msg[0], 256, key[0], 18, cst[0], 16);

	kmac128x4(otp[0], otp[1], otp[2], otp[3], 16, key[0], key[1], key[2], key[3], 18,
		cst[0], cst[1], cst[2], cst[3], 16, msg[0], msg[1], msg[2], msg[3], 256);

	if (qsc_intutils_are_equal8(exp[0], otp[0], sizeof(exp[0])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac128x4_equality: output does not match the known answer -KP1 \n");
		status = false;
	}

	qsc_kmac128_compute(exp[1], 16, msg[1], 256, key[1], 18, cst[1], 16);

	if (qsc_intutils_are_equal8(exp[1], otp[1], sizeof(exp[1])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac128x4_equality: output does not match the known answer -KP2 \n");
		status = false;
	}

	qsc_kmac128_compute(exp[2], 16, msg[2], 256, key[2], 18, cst[2], 16);

	if (qsc_intutils_are_equal8(exp[2], otp[2], sizeof(exp[2])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac128x4_equality: output does not match the known answer -KP3 \n");
		status = false;
	}

	qsc_kmac128_compute(exp[3], 16, msg[3], 256, key[3], 18, cst[3], 16);

	if (qsc_intutils_are_equal8(exp[3], otp[3], sizeof(exp[3])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac128x4_equality: output does not match the known answer -KP4 \n");
		status = false;
	}

	return status;
}

bool qsctest_kmac256x4_equality()
{
	uint8_t cst[4][32] = { 0 };
	uint8_t key[4][34] = { 0 };
	uint8_t msg[4][256] = { 0 };
	uint8_t otp[4][32] = { 0 };
	uint8_t exp[4][32] = { 0 };
	size_t i;
	bool status;

	status = true;

	for (i = 0; i < 32; ++i)
	{
		cst[0][i] = (uint8_t)i;
		cst[1][i] = (uint8_t)i;
		cst[2][i] = (uint8_t)i;
		cst[3][i] = (uint8_t)i;
		key[0][i] = (uint8_t)i;
		key[1][i] = (uint8_t)i;
		key[2][i] = (uint8_t)i;
		key[3][i] = (uint8_t)i;
	}

	key[0][32] = (uint8_t)1;
	key[1][32] = (uint8_t)2;
	key[2][32] = (uint8_t)3;
	key[3][32] = (uint8_t)4;

	for (i = 0; i < 256; ++i)
	{
		msg[0][i] = (uint8_t)i;
		msg[1][i] = (uint8_t)i;
		msg[2][i] = (uint8_t)i;
		msg[3][i] = (uint8_t)i;
	}

	kmac256x4(otp[0], otp[1], otp[2], otp[3], 32, key[0], key[1], key[2], key[3], 34,
		cst[0], cst[1], cst[2], cst[3], 16, msg[0], msg[1], msg[2], msg[3], 256);

	qsc_kmac256_compute(exp[0], 32, msg[0], 256, key[0], 34, cst[0], 16);

	if (qsc_intutils_are_equal8(exp[0], otp[0], sizeof(exp[0])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac256x4_equality: output does not match the known answer -KP1 \n");
		status = false;
	}

	qsc_kmac256_compute(exp[1], 32, msg[1], 256, key[1], 34, cst[1], 16);

	if (qsc_intutils_are_equal8(exp[1], otp[1], sizeof(exp[1])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac256x4_equality: output does not match the known answer -KP2 \n");
		status = false;
	}

	qsc_kmac256_compute(exp[2], 32, msg[2], 256, key[2], 34, cst[2], 16);

	if (qsc_intutils_are_equal8(exp[2], otp[2], sizeof(exp[2])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac256x4_equality: output does not match the known answer -KP3 \n");
		status = false;
	}

	qsc_kmac256_compute(exp[3], 32, msg[3], 256, key[3], 34, cst[3], 16);

	if (qsc_intutils_are_equal8(exp[3], otp[3], sizeof(exp[3])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac256x4_equality: output does not match the known answer -KP4 \n");
		status = false;
	}

	return status;
}

bool qsctest_kmac512x4_equality()
{
	uint8_t cst[4][64] = { 0 };
	uint8_t key[4][66] = { 0 };
	uint8_t msg[4][256] = { 0 };
	uint8_t otp[4][64] = { 0 };
	uint8_t exp[4][64] = { 0 };
	size_t i;
	bool status;

	status = true;

	for (i = 0; i < 64; ++i)
	{
		cst[0][i] = (uint8_t)i;
		cst[1][i] = (uint8_t)i;
		cst[2][i] = (uint8_t)i;
		cst[3][i] = (uint8_t)i;
		key[0][i] = (uint8_t)i;
		key[1][i] = (uint8_t)i;
		key[2][i] = (uint8_t)i;
		key[3][i] = (uint8_t)i;
	}

	key[0][64] = (uint8_t)1;
	key[1][64] = (uint8_t)2;
	key[2][64] = (uint8_t)3;
	key[3][64] = (uint8_t)4;

	for (i = 0; i < 256; ++i)
	{
		msg[0][i] = (uint8_t)i;
		msg[1][i] = (uint8_t)i;
		msg[2][i] = (uint8_t)i;
		msg[3][i] = (uint8_t)i;
	}

	kmac512x4(otp[0], otp[1], otp[2], otp[3], 64, key[0], key[1], key[2], key[3], 66,
		cst[0], cst[1], cst[2], cst[3], 16, msg[0], msg[1], msg[2], msg[3], 256);

	qsc_kmac512_compute(exp[0], 64, msg[0], 256, key[0], 66, cst[0], 16);

	if (qsc_intutils_are_equal8(exp[0], otp[0], sizeof(exp[0])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac512x4_equality: output does not match the known answer -KP1 \n");
		status = false;
	}

	qsc_kmac512_compute(exp[1], 64, msg[1], 256, key[1], 66, cst[1], 16);

	if (qsc_intutils_are_equal8(exp[1], otp[1], sizeof(exp[1])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac512x4_equality: output does not match the known answer -KP2 \n");
		status = false;
	}

	qsc_kmac512_compute(exp[2], 64, msg[2], 256, key[2], 66, cst[2], 16);

	if (qsc_intutils_are_equal8(exp[2], otp[2], sizeof(exp[2])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac512x4_equality: output does not match the known answer -KP3 \n");
		status = false;
	}

	qsc_kmac512_compute(exp[3], 64, msg[3], 256, key[3], 66, cst[3], 16);

	if (qsc_intutils_are_equal8(exp[3], otp[3], sizeof(exp[3])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac512x4_equality: output does not match the known answer -KP4 \n");
		status = false;
	}

	return status;
}

bool qsctest_shake128x4_equality()
{
	uint8_t key[4][18] = { 0 };
	uint8_t otp[4][168] = { 0 };
	uint8_t exp[4][168] = { 0 };
	bool status;

	status = true;

	for (size_t i = 0; i < 16; ++i)
	{
		key[0][i] = (uint8_t)i;
		key[1][i] = (uint8_t)i;
		key[2][i] = (uint8_t)i;
		key[3][i] = (uint8_t)i;
	}

	key[0][16] = (uint8_t)1;
	key[1][16] = (uint8_t)2;
	key[2][16] = (uint8_t)3;
	key[3][16] = (uint8_t)4;

	shake128x4(otp[0], otp[1], otp[2], otp[3], 168, key[0], key[1], key[2], key[3], 18);

	qsc_shake128_compute(exp[0], 168, key[0], 18);

	if (qsc_intutils_are_equal8(exp[0], otp[0], sizeof(exp[0])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake128x4_equality: output does not match the known answer -KP1 \n");
		status = false;
	}

	qsc_shake128_compute(exp[1], 168, key[1], 18);

	if (qsc_intutils_are_equal8(exp[1], otp[1], sizeof(exp[1])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake128x4_equality: output does not match the known answer -KP2 \n");
		status = false;
	}

	qsc_shake128_compute(exp[2], 168, key[2], 18);

	if (qsc_intutils_are_equal8(exp[2], otp[2], sizeof(exp[2])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake128x4_equality: output does not match the known answer -KP3 \n");
		status = false;
	}

	qsc_shake128_compute(exp[3], 168, key[3], 18);

	if (qsc_intutils_are_equal8(exp[3], otp[3], sizeof(exp[3])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake128x4_equality: output does not match the known answer -KP4 \n");
		status = false;
	}

	return status;
}

bool qsctest_shake256x4_equality()
{
	uint8_t key[4][34] = { 0 };
	uint8_t otp[4][136] = { 0 };
	uint8_t exp[4][136] = { 0 };
	bool status;

	status = true;

	for (size_t i = 0; i < 32; ++i)
	{
		key[0][i] = (uint8_t)i;
		key[1][i] = (uint8_t)i;
		key[2][i] = (uint8_t)i;
		key[3][i] = (uint8_t)i;
	}

	key[0][32] = (uint8_t)1;
	key[1][32] = (uint8_t)2;
	key[2][32] = (uint8_t)3;
	key[3][32] = (uint8_t)4;

	shake256x4(otp[0], otp[1], otp[2], otp[3], 136, key[0], key[1], key[2], key[3], 34);

	qsc_shake256_compute(exp[0], 136, key[0], 34);

	if (qsc_intutils_are_equal8(exp[0], otp[0], sizeof(exp[0])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake256x4_equality: output does not match the known answer -KP1 \n");
		status = false;
	}

	qsc_shake256_compute(exp[1], 136, key[1], 34);

	if (qsc_intutils_are_equal8(exp[1], otp[1], sizeof(exp[1])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake256x4_equality: output does not match the known answer -KP2 \n");
		status = false;
	}

	qsc_shake256_compute(exp[2], 136, key[2], 34);

	if (qsc_intutils_are_equal8(exp[2], otp[2], sizeof(exp[2])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake256x4_equality: output does not match the known answer -KP3 \n");
		status = false;
	}

	qsc_shake256_compute(exp[3], 136, key[3], 34);

	if (qsc_intutils_are_equal8(exp[3], otp[3], sizeof(exp[3])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake256x4_equality: output does not match the known answer -KP4 \n");
		status = false;
	}

	return status;
}

bool qsctest_shake512x4_equality()
{
	uint8_t key[4][66] = { 0 };
	uint8_t otp[4][72] = { 0 };
	uint8_t exp[4][72] = { 0 };
	bool status;

	status = true;

	for (size_t i = 0; i < 64; ++i)
	{
		key[0][i] = (uint8_t)i;
		key[1][i] = (uint8_t)i;
		key[2][i] = (uint8_t)i;
		key[3][i] = (uint8_t)i;
	}

	key[0][64] = (uint8_t)1;
	key[1][64] = (uint8_t)2;
	key[2][64] = (uint8_t)3;
	key[3][64] = (uint8_t)4;

	shake512x4(otp[0], otp[1], otp[2], otp[3], 72, key[0], key[1], key[2], key[3], 66);

	qsc_shake512_compute(exp[0], 72, key[0], 66);

	if (qsc_intutils_are_equal8(exp[0], otp[0], sizeof(exp[0])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake512x4_equality: output does not match the known answer -KP1 \n");
		status = false;
	}

	qsc_shake512_compute(exp[1], 72, key[1], 66);

	if (qsc_intutils_are_equal8(exp[1], otp[1], sizeof(exp[1])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake512x4_equality: output does not match the known answer -KP2 \n");
		status = false;
	}

	qsc_shake512_compute(exp[2], 72, key[2], 66);

	if (qsc_intutils_are_equal8(exp[2], otp[2], sizeof(exp[2])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake512x4_equality: output does not match the known answer -KP3 \n");
		status = false;
	}

	qsc_shake512_compute(exp[3], 72, key[3], 66);

	if (qsc_intutils_are_equal8(exp[3], otp[3], sizeof(exp[3])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake512x4_equality: output does not match the known answer -KP4 \n");
		status = false;
	}

	return status;
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
bool qsctest_kmac128x8_equality()
{
	uint8_t cst[8][16] = { 0 };
	uint8_t key[8][18] = { 0 };
	uint8_t msg[8][256] = { 0 };
	uint8_t otp[8][16] = { 0 };
	uint8_t exp[8][16] = { 0 };
	size_t i;
	bool status;

	status = true;

	for (i = 0; i < 16; ++i)
	{
		cst[0][i] = (uint8_t)i;
		cst[1][i] = (uint8_t)i;
		cst[2][i] = (uint8_t)i;
		cst[3][i] = (uint8_t)i;
		cst[4][i] = (uint8_t)i;
		cst[5][i] = (uint8_t)i;
		cst[6][i] = (uint8_t)i;
		cst[7][i] = (uint8_t)i;
		key[0][i] = (uint8_t)i;
		key[1][i] = (uint8_t)i;
		key[2][i] = (uint8_t)i;
		key[3][i] = (uint8_t)i;
		key[4][i] = (uint8_t)i;
		key[5][i] = (uint8_t)i;
		key[6][i] = (uint8_t)i;
		key[7][i] = (uint8_t)i;
	}

	key[0][16] = (uint8_t)1;
	key[1][16] = (uint8_t)2;
	key[2][16] = (uint8_t)3;
	key[3][16] = (uint8_t)4;
	key[4][16] = (uint8_t)1;
	key[5][16] = (uint8_t)2;
	key[6][16] = (uint8_t)3;
	key[7][16] = (uint8_t)4;

	for (i = 0; i < 256; ++i)
	{
		msg[0][i] = (uint8_t)i;
		msg[1][i] = (uint8_t)i;
		msg[2][i] = (uint8_t)i;
		msg[3][i] = (uint8_t)i;
		msg[4][i] = (uint8_t)i;
		msg[5][i] = (uint8_t)i;
		msg[6][i] = (uint8_t)i;
		msg[7][i] = (uint8_t)i;
	}

	kmac128x8(otp[0], otp[1], otp[2], otp[3], otp[4], otp[5], otp[6], otp[7], 16, 
		key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 18,
		cst[0], cst[1], cst[2], cst[3], cst[4], cst[5], cst[6], cst[7], 16, 
		msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], 256);

	qsc_kmac128_compute(exp[0], 16, msg[0], 256, key[0], 18, cst[0], 16);

	if (qsc_intutils_are_equal8(exp[0], otp[0], sizeof(exp[0])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac128x8_equality: output does not match the known answer -KP1 \n");
		status = false;
	}

	qsc_kmac128_compute(exp[1], 16, msg[1], 256, key[1], 18, cst[1], 16);

	if (qsc_intutils_are_equal8(exp[1], otp[1], sizeof(exp[1])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac128x8_equality: output does not match the known answer -KP2 \n");
		status = false;
	}

	qsc_kmac128_compute(exp[2], 16, msg[2], 256, key[2], 18, cst[2], 16);

	if (qsc_intutils_are_equal8(exp[2], otp[2], sizeof(exp[2])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac128x8_equality: output does not match the known answer -KP3 \n");
		status = false;
	}

	qsc_kmac128_compute(exp[3], 16, msg[3], 256, key[3], 18, cst[3], 16);

	if (qsc_intutils_are_equal8(exp[3], otp[3], sizeof(exp[3])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac128x8_equality: output does not match the known answer -KP4 \n");
		status = false;
	}

	qsc_kmac128_compute(exp[4], 16, msg[4], 256, key[4], 18, cst[4], 16);

	if (qsc_intutils_are_equal8(exp[4], otp[4], sizeof(exp[4])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac128x8_equality: output does not match the known answer -KP5 \n");
		status = false;
	}

	qsc_kmac128_compute(exp[5], 16, msg[5], 256, key[5], 18, cst[5], 16);

	if (qsc_intutils_are_equal8(exp[5], otp[5], sizeof(exp[5])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac128x8_equality: output does not match the known answer -KP6 \n");
		status = false;
	}

	qsc_kmac128_compute(exp[6], 16, msg[6], 256, key[6], 18, cst[6], 16);

	if (qsc_intutils_are_equal8(exp[6], otp[6], sizeof(exp[6])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac128x8_equality: output does not match the known answer -KP7 \n");
		status = false;
	}

	qsc_kmac128_compute(exp[7], 16, msg[7], 256, key[7], 18, cst[7], 16);

	if (qsc_intutils_are_equal8(exp[7], otp[7], sizeof(exp[7])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac128x8_equality: output does not match the known answer -KP8 \n");
		status = false;
	}

	return status;
}

bool qsctest_kmac256x8_equality()
{
	uint8_t cst[8][32] = { 0 };
	uint8_t key[8][34] = { 0 };
	uint8_t msg[8][256] = { 0 };
	uint8_t otp[8][32] = { 0 };
	uint8_t exp[8][32] = { 0 };
	size_t i;
	bool status;

	status = true;

	for (i = 0; i < 32; ++i)
	{
		cst[0][i] = (uint8_t)i;
		cst[1][i] = (uint8_t)i;
		cst[2][i] = (uint8_t)i;
		cst[3][i] = (uint8_t)i;
		cst[4][i] = (uint8_t)i;
		cst[5][i] = (uint8_t)i;
		cst[6][i] = (uint8_t)i;
		cst[7][i] = (uint8_t)i;
		key[0][i] = (uint8_t)i;
		key[1][i] = (uint8_t)i;
		key[2][i] = (uint8_t)i;
		key[3][i] = (uint8_t)i;
		key[4][i] = (uint8_t)i;
		key[5][i] = (uint8_t)i;
		key[6][i] = (uint8_t)i;
		key[7][i] = (uint8_t)i;
	}

	key[0][32] = (uint8_t)1;
	key[1][32] = (uint8_t)2;
	key[2][32] = (uint8_t)3;
	key[3][32] = (uint8_t)4;
	key[4][32] = (uint8_t)4;
	key[5][32] = (uint8_t)5;
	key[6][32] = (uint8_t)6;
	key[7][32] = (uint8_t)7;

	for (i = 0; i < 256; ++i)
	{
		msg[0][i] = (uint8_t)i;
		msg[1][i] = (uint8_t)i;
		msg[2][i] = (uint8_t)i;
		msg[3][i] = (uint8_t)i;
		msg[4][i] = (uint8_t)i;
		msg[5][i] = (uint8_t)i;
		msg[6][i] = (uint8_t)i;
		msg[7][i] = (uint8_t)i;
	}

	kmac256x8(otp[0], otp[1], otp[2], otp[3], otp[4], otp[5], otp[6], otp[7], 32, 
		key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 34,
		cst[0], cst[1], cst[2], cst[3], cst[4], cst[5], cst[6], cst[7], 16, 
		msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], 256);

	qsc_kmac256_compute(exp[0], 32, msg[0], 256, key[0], 34, cst[0], 16);

	if (qsc_intutils_are_equal8(exp[0], otp[0], sizeof(exp[0])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac256x8_equality: output does not match the known answer -KP1 \n");
		status = false;
	}

	qsc_kmac256_compute(exp[1], 32, msg[1], 256, key[1], 34, cst[1], 16);

	if (qsc_intutils_are_equal8(exp[1], otp[1], sizeof(exp[1])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac256x8_equality: output does not match the known answer -KP2 \n");
		status = false;
	}

	qsc_kmac256_compute(exp[2], 32, msg[2], 256, key[2], 34, cst[2], 16);

	if (qsc_intutils_are_equal8(exp[2], otp[2], sizeof(exp[2])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac256x8_equality: output does not match the known answer -KP3 \n");
		status = false;
	}

	qsc_kmac256_compute(exp[3], 32, msg[3], 256, key[3], 34, cst[3], 16);

	if (qsc_intutils_are_equal8(exp[3], otp[3], sizeof(exp[3])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac256x8_equality: output does not match the known answer -KP4 \n");
		status = false;
	}

	qsc_kmac256_compute(exp[4], 32, msg[4], 256, key[4], 34, cst[4], 16);

	if (qsc_intutils_are_equal8(exp[4], otp[4], sizeof(exp[4])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac256x8_equality: output does not match the known answer -KP5 \n");
		status = false;
	}

	qsc_kmac256_compute(exp[5], 32, msg[5], 256, key[5], 34, cst[5], 16);

	if (qsc_intutils_are_equal8(exp[5], otp[5], sizeof(exp[5])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac256x8_equality: output does not match the known answer -KP6 \n");
		status = false;
	}

	qsc_kmac256_compute(exp[6], 32, msg[6], 256, key[6], 34, cst[6], 16);

	if (qsc_intutils_are_equal8(exp[6], otp[6], sizeof(exp[6])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac256x8_equality: output does not match the known answer -KP7 \n");
		status = false;
	}

	qsc_kmac256_compute(exp[7], 32, msg[7], 256, key[7], 34, cst[7], 16);

	if (qsc_intutils_are_equal8(exp[7], otp[7], sizeof(exp[7])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac256x8_equality: output does not match the known answer -KP8 \n");
		status = false;
	}

	return status;
}

bool qsctest_kmac512x8_equality()
{
	uint8_t cst[8][64] = { 0 };
	uint8_t key[8][66] = { 0 };
	uint8_t msg[8][256] = { 0 };
	uint8_t otp[8][64] = { 0 };
	uint8_t exp[8][64] = { 0 };
	size_t i;
	bool status;

	status = true;

	for (i = 0; i < 64; ++i)
	{
		cst[0][i] = (uint8_t)i;
		cst[1][i] = (uint8_t)i;
		cst[2][i] = (uint8_t)i;
		cst[3][i] = (uint8_t)i;
		cst[4][i] = (uint8_t)i;
		cst[5][i] = (uint8_t)i;
		cst[6][i] = (uint8_t)i;
		cst[7][i] = (uint8_t)i;
		key[0][i] = (uint8_t)i;
		key[1][i] = (uint8_t)i;
		key[2][i] = (uint8_t)i;
		key[3][i] = (uint8_t)i;
		key[4][i] = (uint8_t)i;
		key[5][i] = (uint8_t)i;
		key[6][i] = (uint8_t)i;
		key[7][i] = (uint8_t)i;
	}

	key[0][64] = (uint8_t)1;
	key[1][64] = (uint8_t)2;
	key[2][64] = (uint8_t)3;
	key[3][64] = (uint8_t)4;
	key[4][64] = (uint8_t)5;
	key[5][64] = (uint8_t)6;
	key[6][64] = (uint8_t)7;
	key[7][64] = (uint8_t)8;

	for (i = 0; i < 256; ++i)
	{
		msg[0][i] = (uint8_t)i;
		msg[1][i] = (uint8_t)i;
		msg[2][i] = (uint8_t)i;
		msg[3][i] = (uint8_t)i;
		msg[4][i] = (uint8_t)i;
		msg[5][i] = (uint8_t)i;
		msg[6][i] = (uint8_t)i;
		msg[7][i] = (uint8_t)i;
	}

	kmac512x8(otp[0], otp[1], otp[2], otp[3], otp[4], otp[5], otp[6], otp[7], 64, 
		key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 66,
		cst[0], cst[1], cst[2], cst[3], cst[4], cst[5], cst[6], cst[7], 16, 
		msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], 256);

	qsc_kmac512_compute(exp[0], 64, msg[0], 256, key[0], 66, cst[0], 16);

	if (qsc_intutils_are_equal8(exp[0], otp[0], sizeof(exp[0])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac512x8_equality: output does not match the known answer -KP1 \n");
		status = false;
	}

	qsc_kmac512_compute(exp[1], 64, msg[1], 256, key[1], 66, cst[1], 16);

	if (qsc_intutils_are_equal8(exp[1], otp[1], sizeof(exp[1])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac512x8_equality: output does not match the known answer -KP2 \n");
		status = false;
	}

	qsc_kmac512_compute(exp[2], 64, msg[2], 256, key[2], 66, cst[2], 16);

	if (qsc_intutils_are_equal8(exp[2], otp[2], sizeof(exp[2])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac512x8_equality: output does not match the known answer -KP3 \n");
		status = false;
	}

	qsc_kmac512_compute(exp[3], 64, msg[3], 256, key[3], 66, cst[3], 16);

	if (qsc_intutils_are_equal8(exp[3], otp[3], sizeof(exp[3])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac512x8_equality: output does not match the known answer -KP4 \n");
		status = false;
	}

	qsc_kmac512_compute(exp[4], 64, msg[4], 256, key[4], 66, cst[4], 16);

	if (qsc_intutils_are_equal8(exp[4], otp[4], sizeof(exp[4])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac512x8_equality: output does not match the known answer -KP5 \n");
		status = false;
	}

	qsc_kmac512_compute(exp[5], 64, msg[5], 256, key[5], 66, cst[5], 16);

	if (qsc_intutils_are_equal8(exp[5], otp[5], sizeof(exp[5])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac512x8_equality: output does not match the known answer -KP6 \n");
		status = false;
	}

	qsc_kmac512_compute(exp[6], 64, msg[6], 256, key[6], 66, cst[6], 16);

	if (qsc_intutils_are_equal8(exp[6], otp[6], sizeof(exp[6])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac512x8_equality: output does not match the known answer -KP7 \n");
		status = false;
	}

	qsc_kmac512_compute(exp[7], 64, msg[7], 256, key[7], 66, cst[7], 16);

	if (qsc_intutils_are_equal8(exp[7], otp[7], sizeof(exp[7])) == false)
	{
		qsctest_print_safe("Failure! qsctest_kmac512x8_equality: output does not match the known answer -KP8 \n");
		status = false;
	}

	return status;
}

bool qsctest_shake128x8_equality()
{
	uint8_t key[8][18] = { 0 };
	uint8_t otp[8][168] = { 0 };
	uint8_t exp[8][168] = { 0 };
	size_t i;
	bool status;

	status = true;

	for (i = 0; i < 16; ++i)
	{
		key[0][i] = (uint8_t)i;
		key[1][i] = (uint8_t)i;
		key[2][i] = (uint8_t)i;
		key[3][i] = (uint8_t)i;
		key[4][i] = (uint8_t)i;
		key[5][i] = (uint8_t)i;
		key[6][i] = (uint8_t)i;
		key[7][i] = (uint8_t)i;
	}

	key[0][16] = (uint8_t)1;
	key[1][16] = (uint8_t)2;
	key[2][16] = (uint8_t)3;
	key[3][16] = (uint8_t)4;
	key[4][16] = (uint8_t)1;
	key[5][16] = (uint8_t)2;
	key[6][16] = (uint8_t)3;
	key[7][16] = (uint8_t)4;

	shake128x8(otp[0], otp[1], otp[2], otp[3], otp[4], otp[5], otp[6], otp[7], 168,
		key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 18);

	qsc_shake128_compute(exp[0], 168, key[0], 18);

	if (qsc_intutils_are_equal8(exp[0], otp[0], sizeof(exp[0])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake128x8_equality: output does not match the known answer -KP1 \n");
		status = false;
	}

	qsc_shake128_compute(exp[1], 168, key[1], 18);

	if (qsc_intutils_are_equal8(exp[1], otp[1], sizeof(exp[1])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake128x8_equality: output does not match the known answer -KP2 \n");
		status = false;
	}

	qsc_shake128_compute(exp[2], 168, key[2], 18);

	if (qsc_intutils_are_equal8(exp[2], otp[2], sizeof(exp[2])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake128x8_equality: output does not match the known answer -KP3 \n");
		status = false;
	}

	qsc_shake128_compute(exp[3], 168, key[3], 18);

	if (qsc_intutils_are_equal8(exp[3], otp[3], sizeof(exp[3])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake128x8_equality: output does not match the known answer -KP4 \n");
		status = false;
	}

	qsc_shake128_compute(exp[4], 168, key[4], 18);

	if (qsc_intutils_are_equal8(exp[4], otp[4], sizeof(exp[4])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake128x8_equality: output does not match the known answer -KP5 \n");
		status = false;
	}

	qsc_shake128_compute(exp[5], 168, key[5], 18);

	if (qsc_intutils_are_equal8(exp[5], otp[5], sizeof(exp[5])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake128x8_equality: output does not match the known answer -KP6 \n");
		status = false;
	}

	qsc_shake128_compute(exp[6], 168, key[6], 18);

	if (qsc_intutils_are_equal8(exp[6], otp[6], sizeof(exp[6])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake128x8_equality: output does not match the known answer -KP7 \n");
		status = false;
	}

	qsc_shake128_compute(exp[7], 168, key[7], 18);

	if (qsc_intutils_are_equal8(exp[7], otp[7], sizeof(exp[7])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake128x8_equality: output does not match the known answer -KP8 \n");
		status = false;
	}

	return status;
}

bool qsctest_shake256x8_equality()
{
	uint8_t key[8][34] = { 0 };
	uint8_t otp[8][136] = { 0 };
	uint8_t exp[8][136] = { 0 };
	size_t i;
	bool status;

	status = true;

	for (i = 0; i < 32; ++i)
	{
		key[0][i] = (uint8_t)i;
		key[1][i] = (uint8_t)i;
		key[2][i] = (uint8_t)i;
		key[3][i] = (uint8_t)i;
		key[4][i] = (uint8_t)i;
		key[5][i] = (uint8_t)i;
		key[6][i] = (uint8_t)i;
		key[7][i] = (uint8_t)i;
	}

	key[0][32] = (uint8_t)1;
	key[1][32] = (uint8_t)2;
	key[2][32] = (uint8_t)3;
	key[3][32] = (uint8_t)4;
	key[4][32] = (uint8_t)1;
	key[5][32] = (uint8_t)2;
	key[6][32] = (uint8_t)3;
	key[7][32] = (uint8_t)4;

	shake256x8(otp[0], otp[1], otp[2], otp[3], otp[4], otp[5], otp[6], otp[7], 136, 
		key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 34);

	qsc_shake256_compute(exp[0], 136, key[0], 34);

	if (qsc_intutils_are_equal8(exp[0], otp[0], sizeof(exp[0])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake256x8_equality: output does not match the known answer -KP1 \n");
		status = false;
	}

	qsc_shake256_compute(exp[1], 136, key[1], 34);

	if (qsc_intutils_are_equal8(exp[1], otp[1], sizeof(exp[1])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake256x8_equality: output does not match the known answer -KP2 \n");
		status = false;
	}

	qsc_shake256_compute(exp[2], 136, key[2], 34);

	if (qsc_intutils_are_equal8(exp[2], otp[2], sizeof(exp[2])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake256x8_equality: output does not match the known answer -KP3 \n");
		status = false;
	}

	qsc_shake256_compute(exp[3], 136, key[3], 34);

	if (qsc_intutils_are_equal8(exp[3], otp[3], sizeof(exp[3])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake256x8_equality: output does not match the known answer -KP4 \n");
		status = false;
	}

	qsc_shake256_compute(exp[4], 136, key[4], 34);

	if (qsc_intutils_are_equal8(exp[4], otp[4], sizeof(exp[4])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake256x8_equality: output does not match the known answer -KP5 \n");
		status = false;
	}

	qsc_shake256_compute(exp[5], 136, key[5], 34);

	if (qsc_intutils_are_equal8(exp[5], otp[5], sizeof(exp[5])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake256x8_equality: output does not match the known answer -KP6 \n");
		status = false;
	}

	qsc_shake256_compute(exp[6], 136, key[6], 34);

	if (qsc_intutils_are_equal8(exp[6], otp[6], sizeof(exp[6])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake256x8_equality: output does not match the known answer -KP7 \n");
		status = false;
	}

	qsc_shake256_compute(exp[7], 136, key[7], 34);

	if (qsc_intutils_are_equal8(exp[7], otp[7], sizeof(exp[7])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake256x8_equality: output does not match the known answer -KP8 \n");
		status = false;
	}

	return status;
}

bool qsctest_shake512x8_equality()
{
	uint8_t key[8][66] = { 0 };
	uint8_t otp[8][72] = { 0 };
	uint8_t exp[8][72] = { 0 };
	size_t i;
	bool status;

	status = true;

	for (i = 0; i < 64; ++i)
	{
		key[0][i] = (uint8_t)i;
		key[1][i] = (uint8_t)i;
		key[2][i] = (uint8_t)i;
		key[3][i] = (uint8_t)i;
		key[4][i] = (uint8_t)i;
		key[5][i] = (uint8_t)i;
		key[6][i] = (uint8_t)i;
		key[7][i] = (uint8_t)i;
	}

	key[0][64] = (uint8_t)1;
	key[1][64] = (uint8_t)2;
	key[2][64] = (uint8_t)3;
	key[3][64] = (uint8_t)4;
	key[4][64] = (uint8_t)1;
	key[5][64] = (uint8_t)2;
	key[6][64] = (uint8_t)3;
	key[7][64] = (uint8_t)4;

	shake512x8(otp[0], otp[1], otp[2], otp[3], otp[4], otp[5], otp[6], otp[7], 72,
		key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 66);

	qsc_shake512_compute(exp[0], 72, key[0], 66);

	if (qsc_intutils_are_equal8(exp[0], otp[0], sizeof(exp[0])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake512x8_equality: output does not match the known answer -KP1 \n");
		status = false;
	}

	qsc_shake512_compute(exp[1], 72, key[1], 66);

	if (qsc_intutils_are_equal8(exp[1], otp[1], sizeof(exp[1])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake512x8_equality: output does not match the known answer -KP2 \n");
		status = false;
	}

	qsc_shake512_compute(exp[2], 72, key[2], 66);

	if (qsc_intutils_are_equal8(exp[2], otp[2], sizeof(exp[2])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake512x8_equality: output does not match the known answer -KP3 \n");
		status = false;
	}

	qsc_shake512_compute(exp[3], 72, key[3], 66);

	if (qsc_intutils_are_equal8(exp[3], otp[3], sizeof(exp[3])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake512x8_equality: output does not match the known answer -KP4 \n");
		status = false;
	}

	qsc_shake512_compute(exp[4], 72, key[4], 66);

	if (qsc_intutils_are_equal8(exp[4], otp[4], sizeof(exp[4])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake512x8_equality: output does not match the known answer -KP5 \n");
		status = false;
	}

	qsc_shake512_compute(exp[5], 72, key[5], 66);

	if (qsc_intutils_are_equal8(exp[5], otp[5], sizeof(exp[5])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake512x8_equality: output does not match the known answer -KP6 \n");
		status = false;
	}

	qsc_shake512_compute(exp[6], 72, key[6], 66);

	if (qsc_intutils_are_equal8(exp[6], otp[6], sizeof(exp[6])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake512x8_equality: output does not match the known answer -KP7 \n");
		status = false;
	}

	qsc_shake512_compute(exp[7], 72, key[7], 66);

	if (qsc_intutils_are_equal8(exp[7], otp[7], sizeof(exp[7])) == false)
	{
		qsctest_print_safe("Failure! qsctest_shake512x8_equality: output does not match the known answer -KP8 \n");
		status = false;
	}

	return status;
}
#endif

void qsctest_sha3_run()
{
	if (qsctest_cshake_256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the cSHAKE-256 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the cSHAKE-256 KAT test. \n");
	}

	if (qsctest_cshake_512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the cSHAKE-512 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the cSHAKE-512 KAT test. \n");
	}

	if (qsctest_kmac_128_kat() == true)
	{
		qsctest_print_safe("Success! Passed the KMAC-128 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KMAC-128 KAT test. \n");
	}

	if (qsctest_kmac_256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the KMAC-256 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KMAC-256 KAT test. \n");
	}

	if (qsctest_kmac_512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the KMAC-512 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KMAC-512 KAT test. \n");
	}

	if (qsctest_sha3_256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the SHA3-256 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SHA3-256 KAT test. \n");
	}

	if (qsctest_sha3_512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the SHA3-512 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SHA3-512 KAT test. \n");
	}

	if (qsctest_shake_256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the SHAKE-256 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SHAKE-256 KAT test. \n");
	}

	if (qsctest_shake_256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the SHAKE-512 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SHAKE-512 KAT test. \n");
	}

	if (qsctest_kpa_256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the KPA-256 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KPA-256 KAT test. \n");
	}

	if (qsctest_kpa_512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the KPA-512 KAT test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KPA-512 KAT test. \n");
	}

#if defined(QSC_SYSTEM_HAS_AVX2)

	if (qsctest_kmac128x4_equality() == true)
	{
		qsctest_print_safe("Success! Passed the KMAC-128 4x SIMD equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KMAC-128 4x SIMD equality test. \n");
	}

	if (qsctest_kmac256x4_equality() == true)
	{
		qsctest_print_safe("Success! Passed the KMAC-256 4x SIMD equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KMAC-256 4x SIMD equality test. \n");
	}

	if (qsctest_kmac512x4_equality() == true)
	{
		qsctest_print_safe("Success! Passed the KMAC-512 4x SIMD equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KMAC-512 4x SIMD equality test. \n");
	}

	if (qsctest_shake128x4_equality() == true)
	{
		qsctest_print_safe("Success! Passed the SHAKE-128 4x SIMD equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SHAKE-128 4x SIMD equality test. \n");
	}

	if (qsctest_shake256x4_equality() == true)
	{
		qsctest_print_safe("Success! Passed the SHAKE-256 4x SIMD equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SHAKE-256 4x SIMD equality test. \n");
	}

	if (qsctest_shake512x4_equality() == true)
	{
		qsctest_print_safe("Success! Passed the SHAKE-512 4x SIMD equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SHAKE-512 4x SIMD equality test. \n");
	}

#endif

#if defined(QSC_SYSTEM_HAS_AVX512)

	if (qsctest_kmac128x8_equality() == true)
	{
		qsctest_print_safe("Success! Passed the KMAC-128 8x SIMD equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KMAC-128 8x SIMD equality test. \n");
	}

	if (qsctest_kmac256x8_equality() == true)
	{
		qsctest_print_safe("Success! Passed the KMAC-256 8x SIMD equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KMAC-256 8x SIMD equality test. \n");
	}

	if (qsctest_kmac512x8_equality() == true)
	{
		qsctest_print_safe("Success! Passed the KMAC-512 8x SIMD equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the KMAC-512 8x SIMD equality test. \n");
	}

	if (qsctest_shake128x8_equality() == true)
	{
		qsctest_print_safe("Success! Passed the SHAKE-128 8x SIMD equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SHAKE-128 8x SIMD equality test. \n");
	}

	if (qsctest_shake256x8_equality() == true)
	{
		qsctest_print_safe("Success! Passed the SHAKE-256 8x SIMD equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SHAKE-256 8x SIMD equality test. \n");
	}

	if (qsctest_shake512x8_equality() == true)
	{
		qsctest_print_safe("Success! Passed the SHAKE-512 8x SIMD equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the SHAKE-512 8x SIMD equality test. \n");
	}

#endif
}
