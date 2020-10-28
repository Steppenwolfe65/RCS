/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2020 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
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
* An implementation of the cryptographic system entropy provider
* Written by John G. Underhill
* Updated on January 20, 2020
* Contact: develop@vtdev.com */

/**
* \file csp.h
* \brief <b>Cryptographic System entropy Provider: CSP</b> \n
* Provides access to either the Windows CryptGenRandom provider or
* the /dev/urandom pool on posix systems.
* This provider is not recommended for stand-alone use, but should be combined
* with another entropy provider to seed a MAC or DRBG function to provide quality
* random output.
* The ACP entropy provider is the recommended provider in this library.
*
* \author John Underhill
* \date June 05, 2019
*/

#ifndef QSC_CSP_H
#define QSC_CSP_H

#include "common.h"

/*!
* \def QSC_CSP_SEED_MAX
* \brief The maximum seed size that can be extracted from a single generate call
*/
#define QSC_CSP_SEED_MAX 1024000

/**
* \brief Get an array of pseudo-random bytes from the system entropy provider.
*
* \param output: Pointer to the output byte array
* \param length: The number of bytes to copy
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_csp_generate(uint8_t* output, size_t length);

#endif
