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
#include "benchmark.h"
#include "cpuid.h"
#include "rcs.h"
#include "rcs_test.h"
#include "sha3_test.h"
#include "testutils.h"
#include <stdio.h>

void print_title()
{
	qsctest_print_safe("*************************************************** \n");
	qsctest_print_safe("* RCS: A symmetric authenticated  stream cipher   * \n");
	qsctest_print_safe("*                                                 * \n");
	qsctest_print_safe("* Release:   v1.0.0.1 (A1)                        * \n");
	qsctest_print_safe("* License:   GPLv3                                * \n");
	qsctest_print_safe("* Date:      December 07, 2020                    * \n");
	qsctest_print_safe("* Contact:   develop@vtdev.com                    * \n");
	qsctest_print_safe("*************************************************** \n");
	qsctest_print_safe("\n");
}

int main()
{
	qsc_cpu_features features;
	bool hfeat;

	hfeat = qsc_runtime_features(&features);

	if (hfeat == false)
	{
		qsctest_print_safe("The CPU type was not recognized on this system! \n");
		qsctest_print_safe("Some features may be disabled. \n\n");
	}

	if (features.has_aesni == true)
	{
		qsctest_print_line("AES-NI is available on this system.");
		qsctest_print_line("The QSC_SYSTEM_AESNI_ENABLED flag has been detected, AES-NI intrinsics are enabled.");
	}
	else
	{
		qsctest_print_line("AES-NI was not detected on this system.");
	}

	if (features.has_avx512 == true)
	{
		qsctest_print_line("The AVX-512 intrinsics functions have been detected on this system.");
	}
	else if (features.has_avx2 == true)
	{
		qsctest_print_line("The AVX-2 intrinsics functions have been detected on this system.");
	}
	else if (features.has_avx == true)
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
	qsctest_print_safe("Enable the QSC_RCS_AUTHENTICATED definition in rcs.h to enable authentication! \n");
#endif

	print_title();

	qsctest_print_line("");
	qsctest_print_line("AVX-512 intrinsics have been fully integrated into this project.");
	qsctest_print_line("On an AVX-512 capable CPU, enable AVX-512 in the project properties for best performance.");
	qsctest_print_line("Enable the maximum available AVX feature set in the project properties (AVX/AVX2/AVX512).");
	qsctest_print_line("");

	qsctest_print_safe("*** Test extended cipher implementations using Stress testing, Monte Carlo, and KAT vector tests from CEX++ *** \n");
	qsctest_rcs_run();
	qsctest_print_line("");

	qsctest_print_safe("*** Test SHAKE, cSHAKE, KMAC, and SHA3 implementations using the official KAT vetors. *** \n");
	qsctest_sha3_run();
	qsctest_print_line("");

	if (qsctest_test_confirm("Press 'Y' then Enter to run Symmetric Cipher Speed Tests, any other key to cancel: ") == true)
	{
		qsctest_rcs_speed_run();
	}

	qsctest_print_safe("Completed! Press any key to close..");
	qsctest_get_wait();

	return 0;
}
