#include "sha2_kat.h"
#include "intutils.h"
#include "sha2.h"
#include "testutils.h"

/* jgu -suppressing misra stdio header warning in example only */
/*lint -e829 */
#include <stdio.h>

bool hkdf_256_kat() 
{
	uint8_t exp0[42] = { 0 };
	uint8_t exp1[82] = { 0 };
	uint8_t inf0[10] = { 0 };
	uint8_t inf1[80] = { 0 };
	uint8_t key0[22] = { 0 };
	uint8_t key1[80] = { 0 };
	uint8_t otp0[42] = { 0 };
	uint8_t otp1[82] = { 0 };
	bool status;

	hex_to_bin("D03C9AB82C884B1DCFD3F4CFFD0E4AD1501915E5D72DF0E6D846D59F6CF78047"
		"39958B5DF06BDE49DB6D", exp0, sizeof(exp0));
	hex_to_bin("24B29E50BD5B2968A8FC1B030B52A07B3B87C45603AAA046D649CD3CAAE06D5C"
		"B029960513275DF28548068821DF861904F0C095D063097A61EF571687217603"
				"E7D7673A7F98AEC538879E81E80864A91BCC", exp1, sizeof(exp1));
	hex_to_bin("F0F1F2F3F4F5F6F7F8F9", inf0, sizeof(inf0));
	hex_to_bin("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
		"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
				"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", inf1, sizeof(inf1));
	hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F", key1, sizeof(key1));

	status = true;

	/* test compact api */

	hkdf256_expand(otp0, sizeof(otp0), key0, sizeof(key0), inf0, sizeof(inf0));

	if (are_equal8(otp0, exp0, sizeof(otp0)) != true)
	{
		status = false;
	}

	hkdf256_expand(otp1, sizeof(otp1), key1, sizeof(key1), inf1, sizeof(inf1));

	if (are_equal8(otp1, exp1, sizeof(otp1)) != true)
	{
		status = false;
	}

	return status;
}

bool hkdf_512_kat()
{
	uint8_t exp0[42] = { 0 };
	uint8_t exp1[82] = { 0 };
	uint8_t inf0[10] = { 0 };
	uint8_t inf1[80] = { 0 };
	uint8_t key0[22] = { 0 };
	uint8_t key1[80] = { 0 };
	uint8_t otp0[42] = { 0 };
	uint8_t otp1[82] = { 0 };
	bool status;

	hex_to_bin("7CE212EEB2A92270C4460A4728944B9B0EE9E060DE13C197853D37A20CE7184F"
		"94390EAEA4C18CEF989D", exp0, sizeof(exp0));
	hex_to_bin("C66BAAA5CFB588D3B99CCC193005CD39C7CBAB0E6682F95E4E7D8B5A92EE3031"
		"6D59BC93F6E2BAC696A05BF448E2C088632691CC9CD3B238042FE564439B9074"
		"5DD4E27DC0E6D779129657F3CF424CA207F3", exp1, sizeof(exp1));
	hex_to_bin("F0F1F2F3F4F5F6F7F8F9", inf0, sizeof(inf0));
	hex_to_bin("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
		"D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF", inf1, sizeof(inf1));
	hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
		"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
		"404142434445464748494A4B4C4D4E4F", key1, sizeof(key1));

	status = true;

	/* test compact api */

	hkdf512_expand(otp0, sizeof(otp0), key0, sizeof(key0), inf0, sizeof(inf0));

	if (are_equal8(otp0, exp0, sizeof(otp0)) != true)
	{
		status = false;
	}

	hkdf512_expand(otp1, sizeof(otp1), key1, sizeof(key1), inf1, sizeof(inf1));

	if (are_equal8(otp1, exp1, sizeof(otp1)) != true)
	{
		status = false;
	}

	return status;
}

bool hmac_256_kat()
{
	uint8_t exp0[SHA2_256_HASH] = { 0 };
	uint8_t exp1[SHA2_256_HASH] = { 0 };
	uint8_t exp2[SHA2_256_HASH] = { 0 };
	uint8_t exp3[SHA2_256_HASH] = { 0 };
	uint8_t key0[20] = { 0 };
	uint8_t key1[20] = { 0 };
	uint8_t key2[25] = { 0 };
	uint8_t key3[131] = { 0 };
	uint8_t msg0[8] = { 0 };
	uint8_t msg1[50] = { 0 };
	uint8_t msg2[50] = { 0 };
	uint8_t msg3[54] = { 0 };
	uint8_t otp[SHA2_256_HASH] = { 0 };
	hmac256_state state;
	bool status;

	hex_to_bin("B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7", exp0, sizeof(exp0));
	hex_to_bin("773EA91E36800E46854DB8EBD09181A72959098B3EF8C122D9635514CED565FE", exp1, sizeof(exp1));
	hex_to_bin("82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8077A2E3FF46729665B", exp2, sizeof(exp2));
	hex_to_bin("60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54", exp3, sizeof(exp3));

	hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", key1, sizeof(key1));
	hex_to_bin("0102030405060708090A0B0C0D0E0F10111213141516171819", key2, sizeof(key2));
	hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAA", key3, sizeof(key3));

	hex_to_bin("4869205468657265", msg0, sizeof(msg0));
	hex_to_bin("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
		"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", msg1, sizeof(msg1));
	hex_to_bin("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"
		"CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD", msg2, sizeof(msg2));
	hex_to_bin("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A"
		"65204B6579202D2048617368204B6579204669727374", msg3, sizeof(msg3));

	status = true;

	/* test compact api */

	hmac256_compute(otp, msg0, sizeof(msg0), key0, sizeof(key0));

	if (are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	hmac256_compute(otp, msg1, sizeof(msg1), key1, sizeof(key1));

	if (are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	hmac256_compute(otp, msg2, sizeof(msg2), key2, sizeof(key2));

	if (are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	hmac256_compute(otp, msg3, sizeof(msg3), key3, sizeof(key3));

	if (are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		status = false;
	}

	/* test long-form api */

	clear8(otp, sizeof(otp));
	/* if message is less than one full block, just call finalize */
	hmac256_initialize(&state, key0, sizeof(key0));
	hmac256_finalize(&state, otp, msg0, sizeof(msg0));

	if (are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		status = false;
	}

	return status;
}

bool hmac_512_kat()
{
	uint8_t exp0[SHA2_512_HASH] = { 0 };
	uint8_t exp1[SHA2_512_HASH] = { 0 };
	uint8_t exp2[SHA2_512_HASH] = { 0 };
	uint8_t exp3[SHA2_512_HASH] = { 0 };
	uint8_t key0[20] = { 0 };
	uint8_t key1[20] = { 0 };
	uint8_t key2[25] = { 0 };
	uint8_t key3[131] = { 0 };
	uint8_t msg0[8] = { 0 };
	uint8_t msg1[50] = { 0 };
	uint8_t msg2[50] = { 0 };
	uint8_t msg3[54] = { 0 };
	uint8_t otp[SHA2_512_HASH] = { 0 };
	hmac512_state state;
	bool status;


	hex_to_bin("87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDE"
		"DAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854", exp0, sizeof(exp0));
	hex_to_bin("FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A3655F83E33B2279D39"
		"BF3E848279A722C806B485A47E67C807B946A337BEE8942674278859E13292FB", exp1, sizeof(exp1));
	hex_to_bin("B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B872DE76F8050361EE3DB"
		"A91CA5C11AA25EB4D679275CC5788063A5F19741120C4F2DE2ADEBEB10A298DD", exp2, sizeof(exp2));
	hex_to_bin("80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEEC1121B013783F8F352"
		"6B56D037E05F2598BD0FD2215D6A1E5295E64F73F63F0AEC8B915A985D786598", exp3, sizeof(exp3));

	hex_to_bin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", key0, sizeof(key0));
	hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", key1, sizeof(key1));
	hex_to_bin("0102030405060708090A0B0C0D0E0F10111213141516171819", key2, sizeof(key2));
	hex_to_bin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", key3, sizeof(key3));

	hex_to_bin("4869205468657265", msg0, sizeof(msg0));
	hex_to_bin("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
		"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", msg1, sizeof(msg1));
	hex_to_bin("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"
		"CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD", msg2, sizeof(msg2));
	hex_to_bin("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A"
		"65204B6579202D2048617368204B6579204669727374", msg3, sizeof(msg3));

	status = true;

	/* test compact api */

	hmac512_compute(otp, msg0, sizeof(msg0), key0, sizeof(key0));

	if (are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	hmac512_compute(otp, msg1, sizeof(msg1), key1, sizeof(key1));

	if (are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	hmac512_compute(otp, msg2, sizeof(msg2), key2, sizeof(key2));

	if (are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	hmac512_compute(otp, msg3, sizeof(msg3), key3, sizeof(key3));

	if (are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		status = false;
	}

	/* test long-form api */

	clear8(otp, sizeof(otp));
	/* if message is less than one full block, just call finalize */
	hmac512_initialize(&state, key0, sizeof(key0));
	hmac512_finalize(&state, otp, msg0, sizeof(msg0));

	if (are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		status = false;
	}

	return status;
}

bool sha2_256_kat()
{
	uint8_t exp0[SHA2_256_HASH] = { 0 };
	uint8_t exp1[SHA2_256_HASH] = { 0 };
	uint8_t exp2[SHA2_256_HASH] = { 0 };
	uint8_t exp3[SHA2_256_HASH] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1[3] = { 0 };
	uint8_t msg2[56] = { 0 };
	uint8_t msg3[112] = { 0 };
	uint8_t otp[SHA2_256_HASH] = { 0 };
	sha256_state state;
	bool status;

	hex_to_bin("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", exp0, sizeof(exp0));
	hex_to_bin("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", exp1, sizeof(exp1));
	hex_to_bin("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1", exp2, sizeof(exp2));
	hex_to_bin("CF5B16A778AF8380036CE59E7B0492370B249B11E8F07A51AFAC45037AFEE9D1", exp3, sizeof(exp3));

	hex_to_bin("00", msg0, sizeof(msg0));
	hex_to_bin("616263", msg1, sizeof(msg1));
	hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg2, sizeof(msg2));
	hex_to_bin("61626364656667686263646566676869636465666768696A6465666768696A6B"
		"65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F"
		"696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F70717273"
		"6D6E6F70717273746E6F707172737475", msg3, sizeof(msg3));

	status = true;

	/* test compact api */

	sha2_compute256(otp, msg0, 0);

	if (are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha2_compute256(otp, msg1, sizeof(msg1));

	if (are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha2_compute256(otp, msg2, sizeof(msg2));

	if (are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha2_compute256(otp, msg3, sizeof(msg3));

	if (are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		status = false;
	}

	/* test long-form api */

	clear8(otp, sizeof(otp));
	/* if message is less than one full block, just call finalize */
	sha256_initialize(&state);
	sha256_finalize(&state, otp, msg0, 0);

	if (are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha256_initialize(&state);
	sha256_finalize(&state, otp, msg1, sizeof(msg1));

	if (are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha256_initialize(&state);
	sha256_finalize(&state, otp, msg2, sizeof(msg2));

	if (are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha256_initialize(&state);

	/* absorb a rate sized block */
	sha256_blockupdate(&state, msg3, 1);

	/* finalize the message */
	sha256_finalize(&state, otp, msg3 + SHA2_256_RATE, sizeof(msg3) - SHA2_256_RATE);

	if (are_equal8(otp, exp3, SHA2_256_HASH) != true)
	{
		status = false;
	}

	return status;
}

bool sha2_384_kat()
{
	uint8_t exp0[SHA2_384_HASH] = { 0 };
	uint8_t exp1[SHA2_384_HASH] = { 0 };
	uint8_t exp2[SHA2_384_HASH] = { 0 };
	uint8_t exp3[SHA2_384_HASH] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1[3] = { 0 };
	uint8_t msg2[56] = { 0 };
	uint8_t msg3[112] = { 0 };
	uint8_t otp[SHA2_384_HASH] = { 0 };
	sha384_state state;
	bool status;

	hex_to_bin("38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA"
		"274EDEBFE76F65FBD51AD2F14898B95B", exp0, sizeof(exp0));
	hex_to_bin("CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED"
		"8086072BA1E7CC2358BAECA134C825A7", exp1, sizeof(exp1));
	hex_to_bin("3391FDDDFC8DC7393707A65B1B4709397CF8B1D162AF05ABFE8F450DE5F36BC6"
		"B0455A8520BC4E6F5FE95B1FE3C8452B", exp2, sizeof(exp2));
	hex_to_bin("09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712"
		"FCC7C71A557E2DB966C3E9FA91746039", exp3, sizeof(exp3));

	hex_to_bin("00", msg0, sizeof(msg0));
	hex_to_bin("616263", msg1, sizeof(msg1));
	hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg2, sizeof(msg2));
	hex_to_bin("61626364656667686263646566676869636465666768696A6465666768696A6B"
		"65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F"
		"696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F70717273"
		"6D6E6F70717273746E6F707172737475", msg3, sizeof(msg3));

	status = true;

	/* test compact api */

	sha2_compute384(otp, msg0, 0);

	if (are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha2_compute384(otp, msg1, sizeof(msg1));

	if (are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha2_compute384(otp, msg2, sizeof(msg2));

	if (are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha2_compute384(otp, msg3, sizeof(msg3));

	if (are_equal8(otp, exp3, sizeof(msg3)) != true)
	{
		status = false;
	}

	/* test long-form api */

	clear8(otp, sizeof(otp));
	/* if message is less than one full block, just call finalize */
	sha384_initialize(&state);
	sha384_finalize(&state, otp, msg0, 0);

	if (are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha384_initialize(&state);
	sha384_finalize(&state, otp, msg1, sizeof(msg1));

	if (are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha384_initialize(&state);
	sha384_finalize(&state, otp, msg2, sizeof(msg2));

	if (are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha384_initialize(&state);

	/* finalize the message */
	sha384_finalize(&state, otp, msg3, sizeof(msg3));

	if (are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		status = false;
	}

	return status;
}

bool sha2_512_kat()
{
	uint8_t exp0[SHA2_512_HASH] = { 0 };
	uint8_t exp1[SHA2_512_HASH] = { 0 };
	uint8_t exp2[SHA2_512_HASH] = { 0 };
	uint8_t exp3[SHA2_512_HASH] = { 0 };
	uint8_t msg0[1] = { 0 };
	uint8_t msg1[3] = { 0 };
	uint8_t msg2[56] = { 0 };
	uint8_t msg3[112] = { 0 };
	uint8_t otp[SHA2_512_HASH] = { 0 };
	sha512_state state;
	bool status;

	hex_to_bin("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE"
		"47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E", exp0, sizeof(exp0));
	hex_to_bin("DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A"
		"2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F", exp1, sizeof(exp1));
	hex_to_bin("204A8FC6DDA82F0A0CED7BEB8E08A41657C16EF468B228A8279BE331A703C335"
		"96FD15C13B1B07F9AA1D3BEA57789CA031AD85C7A71DD70354EC631238CA3445", exp2, sizeof(exp2));
	hex_to_bin("8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018"
		"501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909", exp3, sizeof(exp3));

	hex_to_bin("00", msg0, sizeof(msg0));
	hex_to_bin("616263", msg1, sizeof(msg1));
	hex_to_bin("6162636462636465636465666465666765666768666768696768696A68696A6B"
		"696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071", msg2, sizeof(msg2));
	hex_to_bin("61626364656667686263646566676869636465666768696A6465666768696A6B"
		"65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F"
		"696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F70717273"
		"6D6E6F70717273746E6F707172737475", msg3, sizeof(msg3));

	status = true;

	/* test compact api */

	sha2_compute512(otp, msg0, 0);

	if (are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha2_compute512(otp, msg1, sizeof(msg1));

	if (are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha2_compute512(otp, msg2, sizeof(msg2));

	if (are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha2_compute512(otp, msg3, sizeof(msg3));

	if (are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		status = false;
	}

	/* test long-form api */

	clear8(otp, sizeof(otp));
	/* if message is less than one full block, just call finalize */
	sha512_initialize(&state);
	sha512_finalize(&state, otp, msg0, 0);

	if (are_equal8(otp, exp0, sizeof(exp0)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha512_initialize(&state);
	sha512_finalize(&state, otp, msg1, sizeof(msg1));

	if (are_equal8(otp, exp1, sizeof(exp1)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha512_initialize(&state);
	sha512_finalize(&state, otp, msg2, sizeof(msg2));

	if (are_equal8(otp, exp2, sizeof(exp2)) != true)
	{
		status = false;
	}

	clear8(otp, sizeof(otp));
	sha512_initialize(&state);

	/* finalize the message */
	sha512_finalize(&state, otp, msg3, sizeof(msg3));

	if (are_equal8(otp, exp3, sizeof(exp3)) != true)
	{
		status = false;
	}

	return status;
}
