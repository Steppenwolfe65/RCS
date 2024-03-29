/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "common.h"
#include "benchmark.h"
#include "cpuidex.h"
#include "rcs.h"
#include "rcs_test.h"
#include "sha3_test.h"
#include "testutils.h"
#include <stdio.h>

void print_title()
{
	qsctest_print_line("***************************************************");
	qsctest_print_line("* RCS: An authenticated symmetric stream cipher   *");
	qsctest_print_line("*                                                 *");
	qsctest_print_line("* Release:   v1.0.0.5l (A5)                       *");
	qsctest_print_line("* License:   GPLv3                                *");
	qsctest_print_line("* Date:      December 07, 2021                     *");
	qsctest_print_line("* Contact:   support@digitalfreedomdefence.com    *");
	qsctest_print_line("***************************************************");
	qsctest_print_line("");
}

int main()
{
	qsc_cpuidex_cpu_features cfeat;
	bool res;

	print_title();
	qsctest_print_line("");

	res = qsc_cpuidex_features_set(&cfeat);

	if (res == false)
	{
		qsctest_print_line("The CPU type was not recognized on this system!");
		qsctest_print_line("Some features may be disabled.");
	}

	if (cfeat.aesni == true)
	{
		qsctest_print_line("AES-NI is available on this system.");
#if defined(QSC_SYSTEM_AESNI_ENABLED)
		qsctest_print_line("The AES-NI has been detected; AES-NI intrinsics are enabled.");
#else
		qsctest_print_line("The AES-NI has been detected; AES-NI intrinsics are available but not enabled.");
		qsctest_print_line("Unrem the QSC_SYSTEM_AESNI_ENABLED flag in common.h to enable AES-NI extensions.");
#endif
	}
	else
	{
		qsctest_print_line("AES-NI was not detected on this system.");
	}

	if (cfeat.avx512f == true)
	{
		qsctest_print_line("The AVX-512 intrinsics functions have been detected on this system.");
	}
	else if (cfeat.avx2 == true)
	{
		qsctest_print_line("The AVX-2 intrinsics functions have been detected on this system.");
	}
	else if (cfeat.avx == true)
	{
		qsctest_print_line("The AVX intrinsics functions have been detected on this system.");
	}
	else
	{
		qsctest_print_line("The AVX intrinsics functions have not been detected or are not enabled.");
	}

#if defined(QSC_IS_X86)
	qsctest_print_line("The system is running in X86 mode; for best performance, compile as X64.");
#endif

#if defined(_DEBUG)
	qsctest_print_line("The system is running in Debug mode; for best performance, compile as Release.");
#endif

#if !defined(QSC_CSX_AUTHENTICATED)
	qsctest_print_line("Enable the QSC_RCS_AUTHENTICATED definition in rcs.h to enable authentication!");
#endif

	qsctest_print_line("");
	qsctest_print_line("AVX-512 intrinsics have been fully integrated into this project.");
	qsctest_print_line("On an AVX-512 capable CPU, enable AVX-512 in the project properties for best performance.");
	qsctest_print_line("Enable the maximum available AVX feature set in the project properties (AVX/AVX2/AVX512).");
	qsctest_print_line("");

	if (qsctest_test_confirm("Press 'Y' then Enter to run RCS wellness tests, any other key to cancel: ") == true)
	{
		qsctest_print_line("*** Test extended cipher implementations using Stress testing, Monte Carlo, and KAT vector tests from CEX++ ***");
		qsctest_rcs_run();
		qsctest_print_line("");

		qsctest_print_line("*** Test SHAKE, cSHAKE, KMAC, and SHA3 implementations using the official KAT vetors. ***");
		qsctest_sha3_run();
		qsctest_print_line("");
	}

	if (qsctest_test_confirm("Press 'Y' then Enter to run RCS speed tests, any other key to cancel: ") == true)
	{
		qsctest_rcs_speed_run();
	}

	qsctest_print_line("Completed! Press any key to close..");
	qsctest_get_wait();

	return 0;
}
