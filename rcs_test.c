/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2019 vtdev.com
* This file is part of the CEX Cryptographic library.
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* Test platform for the (RCS/RSX=eAES) symmetric block cipher.
* Contact: develop@vtdev.com */

#include "common.h"
#include "rcs.h"
#include "rcs_kat.h"
#include "sha2_kat.h"
#include "sha3_kat.h"
#include <stdio.h>

/* AES-NI Detection */

#if defined(_MSC_VER)

#include <intrin.h>
#pragma intrinsic(__cpuid)

static int has_aes_ni()
{
	int32_t info[4];
	uint32_t mask;
	int32_t val;

	__cpuid(info, 1);

	if (info[2] != 0)
	{
		mask = (((1UL << 1) - 1) << 25);
		val = (((uint32_t)info[2] & mask) >> 25);
	}
	else
	{
		val = 0;
	}

	return val;
}

#elif defined(__GNUC__)

#include <cpuid.h>
#pragma GCC target ("ssse3")
#pragma GCC target ("sse4.1")
#pragma GCC target ("aes")
#include <x86intrin.h>

static int has_aes_ni()
{
	int info[4];
	int mask;
	int val;

	if (__get_cpuid(1, &info[0], &info[1], &info[2], &info[3]))
	{
		mask = ((((int)1 << 1) - 1) << 25);
		val = ((info[2] & mask) >> 25);
	}
	else
	{
		val = 0;
	}

	return val;
}

#else

static int has_aes_ni()
{
	return 0;
}

#endif

void get_response()
{
	wint_t ret;

	ret = getwchar();
}

/* rcs cipher tests */

void test_rcs_kat()
{
	if (rcs256_kat_test() == true)
	{
		printf_s("Success! Passed the RCS-256 known answer tests. \n");
	}
	else
	{
		printf_s("Failure! Failed the RCS-256 known answer tests. \n");
	}

	if (rcs512_kat_test() == true)
	{
		printf_s("Success! Passed the RCS-512 known answer tests. \n");
	}
	else
	{
		printf_s("Failure! Failed the RCS-512 known answer tests. \n");
	}
}

void test_rcs_stress()
{
	if (rcs256_stress_test() == true)
	{
		printf_s("Success! Passed the RCS-256 stress test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RCS-256 stress test. \n");
	}

	if (rcs512_stress_test() == true)
	{
		printf_s("Success! Passed the RCS-512 stress test. \n");
	}
	else
	{
		printf_s("Failure! Failed the RCS-512 stress test. \n");
	}
}

/* hkdf, hmac, and sha2 tests */

void test_sha2_kat()
{
	if (sha2_256_kat() == true)
	{
		printf_s("Success! Passed the SHA2-256 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the SHA2-256 KAT test. \n");
	}

	if (sha2_512_kat() == true)
	{
		printf_s("Success! Passed the SHA2-512 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the SHA2-512 KAT test. \n");
	}
}

void test_hkdf_kat()
{
	if (hkdf_256_kat() == true)
	{
		printf_s("Success! Passed the HKDF-Expand(HMAC(SHA2-256)) KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the HKDF-Expand(HMAC(SHA2-256)) KAT test. \n");
	}

	if (hkdf_512_kat() == true)
	{
		printf_s("Success! Passed the HKDF-Expand(HMAC(SHA2-512)) KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the HKDF-Expand(HMAC(SHA2-512)) test. \n");
	}
}

void test_hmac_kat()
{
	if (hmac_256_kat() == true)
	{
		printf_s("Success! Passed the HMAC(SHA2-256) KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the HMAC(SHA2-256) KAT test. \n");
	}

	if (hmac_512_kat() == true)
	{
		printf_s("Success! Passed the HMAC(SHA2-512) KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the HMAC(SHA2-512) KAT test. \n");
	}
}

/* shake, cshake, kmac, and sha3 tests */

void test_cshake_kat()
{
	if (cshake_256_kat_test() == true)
	{
		printf_s("Success! Passed the cSHAKE-256 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the cSHAKE-256 KAT test. \n");
	}

	if (cshake_512_kat_test() == true)
	{
		printf_s("Success! Passed the cSHAKE-512 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the cSHAKE-512 KAT test. \n");
	}
}

void test_kmac_kat()
{
	if (kmac_128_kat_test() == true)
	{
		printf_s("Success! Passed the KMAC-128 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the KMAC-128 KAT test. \n");
	}

	if (kmac_256_kat_test() == true)
	{
		printf_s("Success! Passed the KMAC-256 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the KMAC-256 KAT test. \n");
	}

	if (kmac_512_kat_test() == true)
	{
		printf_s("Success! Passed the KMAC-512 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the KMAC-512 KAT test. \n");
	}
}

void test_sha3_kat()
{
	if (sha3_256_kat_test() == true)
	{
		printf_s("Success! Passed the SHA3-256 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the SHA3-256 KAT test. \n");
	}

	if (sha3_512_kat_test() == true)
	{
		printf_s("Success! Passed the SHA3-512 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the SHA3-512 KAT test. \n");
	}
}

void test_shake_kat()
{
	if (shake_256_kat_test() == true)
	{
		printf_s("Success! Passed the SHAKE-256 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the SHAKE-256 KAT test. \n");
	}

	if (shake_512_kat_test() == true)
	{
		printf_s("Success! Passed the SHAKE-512 KAT test. \n");
	}
	else
	{
		printf_s("Failure! Failed the SHAKE-512 KAT test. \n");
	}
}

int main()
{
	int valid;

	valid = 1;

	if (has_aes_ni() == 1)
	{
		printf_s("AES-NI is available on this system. \n");
#if !defined(RCS_AESNI_ENABLED)
		printf_s("Add the RCS_AESNI_ENABLED flag to the preprocessor definitions to test AES-NI implementation. \n");
#else
		printf_s("The RCS_AESNI_ENABLED flag has been detected, AES-NI intrinsics are enabled. \n");
#endif
		printf_s("\n");
	}
	else
	{
		printf_s("AES-NI was not detected on this system. \n");
#if defined(RCS_AESNI_ENABLED)
		printf_s("Remove the RCS_AESNI_ENABLED flag from the preprocessor definitions to test the fallback implementation. \n");
		printf_s("Configuration settings error; AES-NI is enabled but not available on this system, check your compiler preprocessor settings. \n");
		printf_s("\n");
		valid = 0;
#endif
	}

#ifdef RCS_HMAC_EXTENSION
	printf_s("The HMAC authentication extension is enabled. \n");
	printf_s("Remove the RCS_HMAC_EXTENSION definition from the preprocessor flags to enable KMAC authentication. \n");
	printf_s("\n\n");
#else
	printf_s("The default KMAC authentication extension is enabled. \n");
	printf_s("Add the RCS_HMAC_EXTENSION definition to enable the HMAC authentication extension. \n");
	printf_s("\n\n");
#endif

	if (valid == 1)
	{
		printf_s("*** Test extended cipher implementations using Stress testing, Monte Carlo, and KAT vector tests from CEX++ *** \n");
		test_rcs_kat();
		test_rcs_stress();
		printf_s("\n");

		printf_s("*** Test HKDF, HMAC, and SHA2 implementations using the official KAT vetors. *** \n");
		test_hkdf_kat();
		test_hmac_kat();
		test_sha2_kat();
		printf_s("\n");

		printf_s("*** Test SHAKE, cSHAKE, KMAC, and SHA3 implementations using the official KAT vetors. *** \n");
		test_shake_kat();
		test_cshake_kat();
		test_kmac_kat();
		test_sha3_kat();
		printf_s("\n");

		printf_s("Completed! Press any key to close..");
		get_response();
	}
	else
	{
		printf_s("The test has been cancelled. Press any key to close..");
		get_response();
	}

	return 0;
}

