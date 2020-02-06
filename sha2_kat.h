#ifndef QSCTEST_SHA2_KAT_H
#define QSCTEST_SHA2_KAT_H

#include "common.h"

/**
* \file sha3_kat.h
* \brief <b>SHA2, HKDF, and HMAC, Known Answer Tests</b> \n
* Uses Known Answer Tests from official sources to verify the
* correct operation of the SHA2 digests, HKDF, and HMAC implementations.
* \author John Underhill
* \date October 10, 2019
*/

/**
* \brief Tests the 256-bit version of the HFDF-Expand(HMAC(SHA2-256)) key derivation function for correct operation,
* using vectors from the official kat file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* Uses vectors from: RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
* KAT: <a href="http://tools.ietf.org/html/rfc5869">RFC 5869</a>
*/
bool hkdf_256_kat();

/**
* \brief Tests the 512-bit version of the HFDF-Expand(HMAC(SHA2-512)) key derivation function for correct operation,
* using vectors from the official kat file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* Uses vectors from: RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
* KAT: <a href="http://tools.ietf.org/html/rfc5869">RFC 5869</a>
*/
bool hkdf_512_kat();

/**
* \brief Tests the 256-bit version of the HMAC(SHA2-256) function for correct operation,
* using vectors from the official kat file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* Using vectors from: RFC 4321: Test Vectors for the SHA2-256 HMAC:
* KAT: <a href="http://tools.ietf.org/html/rfc4231">RFC 4321</a>
*/
bool hmac_256_kat();

/**
* \brief Tests the 512-bit version of the HMAC(SHA2-512) function for correct operation,
* using vectors from the official kat file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* Using vectors from: RFC 4321: Test Vectors for the SHA2-512 HMAC:
* KAT: <a href="http://tools.ietf.org/html/rfc4231">RFC 4321</a>
*/
bool hmac_512_kat();

/**
* \brief Tests the 256-bit version of the SHA2 message digest for correct operation,
* using selected vectors from the NIST SHA2 official kat file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* KAT: <a href="https://www.di-mgt.com.au/sha_testvectors.html">SHA256</a>
*/
bool sha2_256_kat();

/**
* \brief Tests the 384 bit version of the SHA2 message digest for correct operation,
* using selected vectors from the NIST SHA2 official kat file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* KAT: <a href="https://www.di-mgt.com.au/sha_testvectors.html">SHA384</a>
*/
bool sha2_384_kat();

/**
* \brief Tests the 512-bit version of the SHA2 message digest for correct operation,
* using selected vectors from the NIST SHA2 official kat file.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* KAT: <a href="https://www.di-mgt.com.au/sha_testvectors.html">SHA512</a>
*/
bool sha2_512_kat();

#endif
