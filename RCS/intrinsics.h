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

#ifndef QSC_INTRINSICS_H
#define QSC_INTRINSICS_H

/* \cond DOXYGEN_IGNORE */

/**
* \file intrinsics.h
* \brief SIMD include files
*/

#include "common.h"

#if defined(QSC_SYSTEM_COMPILER_MSC)
#	if defined(QSC_SYSTEM_ARCH_ARM)
#		include <arm_neon.h>
#	else
#		include <intrin.h>	/* Microsoft C/C++ compatible compiler */
#	endif
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#	include <x86intrin.h>	/* GCC-compatible compiler, targeting x86/x86-64 */
#elif defined(__GNUC__) && defined(__ARM_NEON__)
#	include <arm_neon.h>	/* GCC-compatible compiler, targeting ARM with NEON */
#elif defined(__GNUC__) && defined(__IWMMXT__)
#	include <mmintrin.h>	/* GCC-compatible compiler, targeting ARM with WMMX */
#elif (defined(__GNUC__) || defined(__xlC__)) && (defined(__VEC__) || defined(__ALTIVEC__))
#	include <altivec.h>		/* XLC or GCC-compatible compiler, targeting PowerPC with VMX/VSX */
#elif defined(__GNUC__) && defined(__SPE__)
#	include <spe.h>			/* GCC-compatible compiler, targeting PowerPC with SPE */
#endif

/* \endcond DOXYGEN_IGNORE */

#endif
