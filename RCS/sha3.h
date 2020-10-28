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
* An implementation of the SHA3 message digest, KMAC, SHAKE, and CSHAKE
* Written by John G. Underhill
* Updated on October 20, 2020
* Contact: develop@vtdev.com */

/**
* \file sha3.h
* \author John Underhill
* \date October 27, 2019
* \updated October 20, 2020
*
* \brief <b>SHA3 header definition</b> \n
* Contains the public api and documentation for SHA3 digest, SHAKE, cSHAKE, and KMAC implementations.
*
* <b>Usage Examples</b> \n
*
* <b>SHA3-512 hash computation using long-form api</b> \n
* \code
* // external message array
* #define MSGLEN 200
* uint8_t msg[MSGLEN] = {...};
* ...
*
* uint8_t hash[QSC_SHA3_512_HASH_SIZE] = { 0 };
* qsc_keccak_state ctx;
*
* // initialize the state
* qsc_sha3_initialize(ctx.state);
*
* // update the message
* qsc_sha3_update(&ctx, keccak_rate_512, msg, MSGLEN);
*
* // finalize the message and generate the hash
* qsc_sha3_finalize(&ctx, keccak_rate_512, hash);
*
* \endcode
*
* <b>KMAC-256 MAC code generation using long-form api</b> \n
* \code
* // external message and key arrays
* #define MSGLEN 200
* uint8_t msg[MSGLEN] = {...};
* uint8_t key[QSC_KMAC_256_KEY_SIZE] = {...};
* uint8_t cust[...] = {...};
* qsc_keccak_state ctx;
* uint8_t code[QSC_KMAC_256_MAC_SIZE] = { 0 };
*
* // initialize the state with the key and optional custom array
* qsc_kmac_initialize(&ctx, keccak_rate_256, key, sizeof(key), cust, sizeof(cust));
*
* // process the message
* 	qsc_kmac_update(&ctx, keccak_rate_256, msg, MSGLEN);
*
* // finalize the message and generate the hash
* qsc_kmac_finalize(&ctx, keccak_rate_256, code, sizeof(code));
*
* \endcode
*
* <b>cSHAKE-512 pseudo-random generation using long-form api</b> \n
* \code
*
* uint8_t output[64] = { 0 };
* uint8_t key[QSC_KMAC_512_KEY_SIZE] = {...};
* uint8_t cust[...] = {...};
* uint8_t name[...] = {...};
* qsc_keccak_state ctx;
*
* // initialize cSHAKE with the key and optional name and custom arrays
* qsc_cshake_initialize(&ctx, key, sizeof(key), name, sizeof(name), cust, sizeof(cust));
*
* // generate one block of pseudo-random
* qsc_cshake_squeezeblocks(&ctx, output, 1);
* \endcode
*
* \remarks
* \paragraph The SHA3, SHAKE, cSHAKE, and KMAC implementations all share two forms of api: short-form and long-form. \n
* The short-form api, which initializes the state, processes a message, and finalizes by producing output, all in a single function call,
* for example; qsc_sha3_compute512(uint8_t* output, const uint8_t* message, size_t msglen),
* the entire message array is processed and the hash code is written to the output array. \n
* The long-form api uses an initialization call to prepare the state, a blockupdate call if the message is longer than a single message block,
* and the finalize call, which finalizes the state and generates a hash, mac-code, or an array of pseudo-random. \n
* Each of the function families (SHA3, SHAKE, KMAC), have a corresponding set of reference constants associated with that member, example;
* SHAKE_256_KEY is the minimum expected SHAKE-256 key size in bytes, QSC_KMAC_512_MAC_SIZE is the minimum size of the KMAC-512 output mac-code output array,
* and QSC_KECCAK_512_RATE is the SHA3-512 message absorbtion rate.
*
* For additional usage examples, see sha3_test.h. \n
*
* \section Links
* NIST: SHA3 Fips202 http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf \n
* NIST: SP800-185 http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf \n
* NIST: SHA3 Keccak Submission http://keccak.noekeon.org/Keccak-submission-3.pdf \n
* NIST: SHA3 Keccak Slides http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf \n
* NIST: SHA3 Third-Round Report http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf \n
* Team Keccak: Specifications summary https://keccak.team/keccak_specs_summary.html
*
*/

#ifndef QSC_SHA3_H
#define QSC_SHA3_H

#include "common.h"

/*!
* \def QSC_KECCAK_128_RATE
* \brief The KMAC-128 byte absorption rate
*/
#define QSC_KECCAK_128_RATE 168

/*!
* \def QSC_KECCAK_256_RATE
* \brief The KMAC-256 byte absorption rate
*/
#define QSC_KECCAK_256_RATE 136

/*!
* \def QSC_KECCAK_512_RATE
* \brief The KMAC-512 byte absorption rate
*/
#define QSC_KECCAK_512_RATE 72

/*!
* \def QSC_KECCAK_STATE_SIZE
* \brief The Keccak SHA3 uint64 state array size
*/
#define QSC_KECCAK_STATE_SIZE 25

/*!
* \def QSC_KECCAK_STATE_BYTE_SIZE
* \brief The Keccak SHA3 state size in bytes
*/
#define QSC_KECCAK_STATE_BYTE_SIZE 200

/*!
* \def QSC_KMAC_256_KEY_SIZE
* \brief The KMAC-256 key size in bytes
*/
#define QSC_KMAC_256_KEY_SIZE 32

/*!
* \def QSC_KMAC_512_KEY_SIZE
* \brief The KMAC-512 key size in bytes
*/
#define QSC_KMAC_512_KEY_SIZE 64

/*!
* \def QSC_SHA3_256_HASH_SIZE
* \brief The SHA-256 hash size in bytes
*/
#define QSC_SHA3_256_HASH_SIZE 32

/*!
* \def QSC_SHA3_512_HASH_SIZE
* \brief The SHA-512 hash size in bytes
*/
#define QSC_SHA3_512_HASH_SIZE 64

/*!
* \def SHAKE_256_KEY
* \brief The SHAKE-256 key size in bytes
*/
#define QSC_SHAKE_256_KEY_SIZE 32

/*!
* \def SHAKE_512_KEY
* \brief The SHAKE-512 key size in bytes
*/
#define QSC_SHAKE512_KEY_SIZE 64

/* common */

/*!
* \struct qsc_keccak_state
* \brief The Keccak state array; state array must be initialized by the caller
*/
QSC_EXPORT_API typedef struct
{
	uint64_t state[QSC_KECCAK_STATE_SIZE];
	uint8_t buffer[QSC_KECCAK_STATE_BYTE_SIZE];
	size_t position;
} qsc_keccak_state;

/*!
* \enum keccak_rate
* \brief The Keccak rate; determines which security strength is used by the function, 128, 256, or 512-bit
*/
QSC_EXPORT_API typedef enum
{
	keccak_rate_128 = QSC_KECCAK_128_RATE,
	keccak_rate_256 = QSC_KECCAK_256_RATE,
	keccak_rate_512 = QSC_KECCAK_512_RATE,
} keccak_rate;

/**
* \brief Dispose of the Keccak state.
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
QSC_EXPORT_API void qsc_keccak_dispose(qsc_keccak_state* ctx);

/* sha3 */

/**
* \brief Process a message with SHA3-256 and return the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output:: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
QSC_EXPORT_API void qsc_sha3_compute256(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Process a message with SHA3-512 and return the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 64 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
QSC_EXPORT_API void qsc_sha3_compute512(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Update SHA3 with message input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs the input message into the state.
*
* \warning State must be initialized by the caller.
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
QSC_EXPORT_API void qsc_sha3_update(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen);

/**
* \brief Finalize the message state and returns the hash value in output.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Absorb the last block of message and create the hash value. \n
* Produces a 32 byte output code using QSC_KECCAK_256_RATE, 64 bytes with QSC_KECCAK_512_RATE.
*
* \warning The output array must be sized correctly corresponding to the absorbtion rate ((200 - rate) / 2). \n
* Finalizes the message state, can not be used in consecutive calls.
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param output: The output byte array; receives the hash code
*/
QSC_EXPORT_API void qsc_sha3_finalize(qsc_keccak_state* ctx, keccak_rate rate, uint8_t* output);

/**
* \brief Initializes a SHA3 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
*/
QSC_EXPORT_API void qsc_sha3_initialize(qsc_keccak_state* ctx);

/**
* \brief The Keccak permute function.
* Internal function: Permutes the state array, can be used in external constrictions.
*
* \param ctx: [struct] The function state; must be initialized
*/
QSC_EXPORT_API void qsc_keccak_permute(uint64_t* ctx);

/* shake */

/**
* \brief Key a SHAKE-128 instance, and generate an array of pseudo-random bytes.
* Short form api: processes the key and generates the pseudo-random output with a single call.
*
* \warning The output array length must not be zero.
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
*/
QSC_EXPORT_API void qsc_shake128_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen);

/**
* \brief Key a SHAKE-256 instance, and generate an array of pseudo-random bytes.
* Short form api: processes the key and generates the pseudo-random output with a single call.
*
* \warning The output array length must not be zero.
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
*/
QSC_EXPORT_API void qsc_shake256_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen);

/**
* \brief Key a SHAKE-512 instance, and generate an array of pseudo-random bytes.
* Short form api: processes the key and generates the pseudo-random output with a single call.
*
* \warning The output array length must not be zero.
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
*/
QSC_EXPORT_API void qsc_shake512_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen);

/**
* \brief The SHAKE initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Absorb and finalize an input key byte array.
*
* \warning Finalizes the key state, should not be used in consecutive calls. \n
* State must be initialized by the caller.
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
*/
QSC_EXPORT_API void qsc_shake_initialize(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen);

/**
* \brief The SHAKE squeeze function.
* Long form api: must be used in conjunction with the initialize function.
* Permutes and extracts the state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
*/
QSC_EXPORT_API void qsc_shake_squeezeblocks(qsc_keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t nblocks);

/* cshake */

/**
* \brief Key a cSHAKE-128 instance and generate pseudo-random output.
* Short form api: processes the key, name, and custom inputs and generates the pseudo-random output with a single call.
* Permutes and extracts the state to an output byte array..
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
QSC_EXPORT_API void qsc_cshake128_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen);

/**
* \brief Key a cSHAKE-256 instance and generate pseudo-random output.
* Short form api: processes the key, name, and custom inputs and generates the pseudo-random output with a single call.
* Permutes and extracts the state to an output byte array.
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
QSC_EXPORT_API void qsc_cshake256_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen);

/**
* \brief Key a cSHAKE-512 instance and generate pseudo-random output.
* Short form api: processes the key, name, and custom inputs and generates the pseudo-random output with a single call.
* Permutes and extracts the state to an output byte array.
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
QSC_EXPORT_API void qsc_cshake512_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen);

/**
* \brief The cSHAKE-128 initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Initialize the name and customization strings into the state.
*
* \warning State must be initialized by the caller.
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
QSC_EXPORT_API void qsc_cshake_initialize(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen);

/**
* \brief The cSHAKE squeeze function.
* Long form api: must be used in conjunction with the initialize function.
* Permutes and extracts blocks of state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
*/
QSC_EXPORT_API void qsc_cshake_squeezeblocks(qsc_keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t nblocks);

/**
* \brief The cSHAKE update function.
* Long form api: must be used in conjunction with the initialize and squeezeblocks functions.
* Finalize an input key directly into the state.
*
* \warning Finalizes the key state, should not be used in consecutive calls. \n
* State must be initialized by the caller.
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
*/
QSC_EXPORT_API void qsc_cshake_update(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen);

/* kmac */

/**
* \brief Key a KMAC-128 instance and generate a MAC code.
* Short form api: processes the key and custom inputs and generates the MAC code with a single call.
* Key the MAC generator process a message and output the MAC code.
*
* \param output: The mac code byte array
* \param outlen: The number of mac code bytes to generate
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
QSC_EXPORT_API void qsc_kmac128_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen);

/**
* \brief Key a KMAC-256 instance and generate a MAC code.
* Short form api: processes the key and custom inputs and generates the MAC code with a single call.
* Key the MAC generator process a message and output the MAC code.
*
* \param output: The mac code byte array
* \param outlen: The number of mac code bytes to generate
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
QSC_EXPORT_API void qsc_kmac256_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen);

/**
* \brief Key a KMAC-512 instance and generate a MAC code.
* Short form api: processes the key and custom inputs and generates the MAC code with a single call.
* Key the MAC generator process a message and output the MAC code.
*
* \param output: The mac code byte array
* \param outlen: The number of mac code bytes to generate
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
QSC_EXPORT_API void qsc_kmac512_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen);

/**
* \brief The KMAC message update function.
* Long form api: must be used in conjunction with the initialize and finalize functions.
*
* \warning qsc_kmac128_initialize must be called before this function to key and initialize the state. \n
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
QSC_EXPORT_API void qsc_kmac_update(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* message, size_t msglen);

/**
* \brief The KMAC finalize function.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Final processing and calculation of the MAC code.
*
* \warning qsc_kmac128_initialize must be called before this function to key and initialize the state. \n
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param output: The output byte array
* \param outlen: The number of bytes to extract
*/
QSC_EXPORT_API void qsc_kmac_finalize(qsc_keccak_state* ctx, keccak_rate rate, uint8_t* output, size_t outlen);

/**
* \brief Initialize a KMAC instance.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
* Key the MAC generator and initialize the internal state.
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
QSC_EXPORT_API void qsc_kmac_initialize(qsc_keccak_state* ctx, keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen);

/* kpa - Keccak-based Parallel Authentication */

#if defined(QSC_SYSTEM_HAS_AVX512) || defined(QSC_SYSTEM_HAS_AVX2)
#define QSC_KPA_AVX_PARALLEL
#endif

/*!
* \def QSC_KPA_256_KEY_SIZE
* \brief The KPA-256 key size in bytes
*/
#define QSC_KPA_256_KEY_SIZE 32

/*!
* \def QSC_KPA_512_KEY_SIZE
* \brief The KPA-512 key size in bytes
*/
#define QSC_KPA_512_KEY_SIZE 64

/*!
* \def QSC_KPA_ROUNDS
* \brief The number of Keccak rounds used by a KPA permutation
*/
#define QSC_KPA_ROUNDS 12

/*!
* \def QSC_KPA_PARALLELISM
* \brief The KPA degree of parallelization
*/
#define QSC_KPA_PARALLELISM 8

/*!
* \struct qsc_kpa_state
* \brief The KPA state array; state array must be initialized by the caller
*/
QSC_EXPORT_API typedef struct
{
#if defined(QSC_SYSTEM_HAS_AVX512)
	__m512i statew[QSC_KECCAK_STATE_SIZE];
#elif defined(QSC_SYSTEM_HAS_AVX2)
	__m256i statew[2][QSC_KECCAK_STATE_SIZE];
#endif

	uint64_t state[8][QSC_KECCAK_STATE_SIZE];
	uint8_t buffer[8 * QSC_KECCAK_STATE_BYTE_SIZE];
	size_t position;
	size_t processed;
	keccak_rate rate;
} qsc_kpa_state;

/**
* \brief The KPA finalize function.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Final processing and calculation of the MAC code.
*
* \warning qsc_kpa_initialize must be called before this function to key and initialize the state. \n
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param output: The output byte array
* \param outlen: The number of bytes to extract
*/
QSC_EXPORT_API void qsc_kpa_finalize(qsc_kpa_state* ctx, uint8_t* output, size_t outlen);

/**
* \brief Initialize a KPA instance.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
* Key the MAC generator and initialize the internal state.
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
QSC_EXPORT_API void qsc_kpa_initialize(qsc_kpa_state* ctx, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen);

/**
* \brief The KPA message update function.
* Long form api: must be used in conjunction with the initialize and finalize functions.
*
* \warning qsc_kpa_initialize must be called before this function to key and initialize the state. \n
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
QSC_EXPORT_API void qsc_kpa_update(qsc_kpa_state* ctx, const uint8_t* message, size_t msglen);

#endif
