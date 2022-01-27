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

#ifndef QSC_RCS_H
#define QSC_RCS_H

/**
* \file rcs.h
* \brief RCS function definitions \n
* Rijndael-256 authenticated Cipher Stream.
*
* \author		John G. Underhill
* \version		1.0.0.0f
* \date			October 20, 2019
* \updated		January 22, 2022
* \contact:		support@digitalfreedomdefence.com
* \copyright	GPL version 3 license (GPLv3)
*
*
* RCS-256 encryption example \n
* \code
* // external message, key, nonce, and custom-info arrays
* #define CSTLEN 20
* #define MSGLEN 200
* uint8_t cust[CSTLEN] = {...};
* uint8_t key[QSC_RCS256_KEY_SIZE] = {...};
* uint8_t msg[MSGLEN] = {...};
* uint8_t nonce[QSC_RCS_BLOCK_SIZE] = {...};
* ...
* uint8_t cpt[MSGLEN + QSC_RCS256_MAC_SIZE] = { 0 };
* qsc_rcs_state state;
* qsc_rcs_keyparams kp = { key, QSC_RCS256_KEY_SIZE, nonce, cust, CSTLEN };
*
* // initialize the state
* qsc_rcs_initialize(&state, &kp, true);
* // encrypt the message
* qsc_rcs_transform(&state, cpt, msg, MSGLEN)
* \endcode
*
* RCS-256 decryption example \n
* \code
* // external cipher-text, key and custom-info arrays,
* // and cipher-text containing the encrypted plain-text and the mac-code
* uint8_t cpt[CPTLEN] = { qsc_rcs_transform(k,p) }
* uint8_t key[QSC_RCS256_KEY_SIZE] = {...};
* uint8_t nonce[QSC_RCS_BLOCK_SIZE] = {...};
* uint8_t cust[CSTLEN] = {...};
* ...
* // subtract the mac-code length from the overall cipher-text length for the message size
* const size_t MSGLEN = CPTLEN - QSC_RCS256_MAC_SIZE;
* uint8_t msg[MSGLEN] = { 0 };
* qsc_rcs_keyparams kp = { key, QSC_RCS256_KEY_SIZE, nonce, cust, CSTLEN };
*
* // initialize the cipher state for decryption
* qsc_rcs_initialize(&state, &kp, false);
*
* // authenticate and decrypt the cipher-text
* if (rcs256_transform(&state, msg, cpt, MSGLEN) == false)
* {
*	// authentication has failed, do something..
* }
* \endcode
*
* \remarks
* \par
* The RCS (Rijndael-256 authenticated Cipher Stream) encryption functions, are a hybrid of the Rijndael-256 rounds function,
* and a cryptographically strong pseudo-random generator function (cSHAKE) used to expand the round-key array (the key-schedule). \n
* The cryptographic XOF, generates the round key array used by the Rijndael rounds function, enabling the safe addition of increased mixing rounds,
* and replacing the differentially-weak native Rijndael key-schedule expansion function. \n
* The cipher increases the number of mixing rounds from 14 used by AES-256, to 22 used by RCS-256, twice the best known classical computer attack. \n
* The cipher also has a 512-bit key configuration, which uses 30 rounds of mixing. \n
* There are attacks now being proposed, that strongly indicate that larger key sizes will be necessary against future quantum-based attacks on symmetric ciphers.
*
* \par
* The pseudo-random bytes generator used by this cipher is the Keccak cSHAKE extended output function (XOF).
* The cSHAKE XOF is implemented in 256 and 512-bit forms of those functions, correlating to the input cipher-key size.
* The cipher has two base variants; RCS256 and RCS512, the 256 variant using a 256-bit input key, and RCS512 using a 512-bit key.
* This change in key schedule expansion functions to the stronger Keccak based XOF function, can now can safely produce a larger round-key array,
* unlocking an increased number of mixing rounds, and preventing many serious forms of attack on the Rijndael-based ciphers.
*
* \par
* This is a 'tweakable cipher', the initialization parameters; qsc_rcs_keyparams, include an info parameter that can be used as a secondary user input.
* Internally, the info parameter is used to customize the cSHAKE output, using the cSHAKE 'custom' parameter to pre-initialize the SHAKE state.
* The info parameter can be tweaked, with a user defined string 'info' in an qsc_rcs_keyparams structure passed to the rcs_intitialize(state,keyparams,encrypt,mode).
* This tweak can be used as a 'domain key', or to differentiate cipher-text output from other implementations, or as a secondary secret-key input.
*
* \par
* RCS is an authenticated encryption with associated data (AEAD) stream cipher.
* It uses the hash-based key schedule extended form of Rijndael-256, wrapped in a segmented integer counter mode (CTR) for encryption.
* The cSHAKE key-schedule function also generates a key for the keyed hash-based MAC funtion; KMAC, used to generate the authentication code,
* which is appended to the cipher-text output of an encryption call.
* In decryption mode, before decryption is performed, an internal mac code is calculated, and compared to the code embedded in the cipher-text.
* If authentication fails, the cipher-text is not decrypted, and the qsc_rcs_transform(state,out,in,inlen) function returns a boolean false value.
* The qsc_rcs_set_associated(state,in,inlen) function can be used to add additional data to the MAC generators input, like packet-header data, or a custom code or counter.
*
* \par
* This implementation has both a C reference code, and an implementation that uses the AES-NI instructions that are used in the AES and RCS cipher variants. \n
* The AES-NI implementation can be enabled by adding the QSC_RCS_AESNI_ENABLED constant to your preprocessor definitions. \n
* The RCS-256, RCS-512, known answer vectors are taken from the CEX++ cryptographic library <a href="https://github.com/Steppenwolfe65/CEX">The CEX++ Cryptographic Library</a>. \n
* See the documentation and the rcs_test.h tests for usage examples.
* To enable the AES-NI implementation, uncomment the definition in this file or add QSC_RCS_AESNI_ENABLED or add it to the compiler preprocessor definitions. \n
*/

/* TODO: Test KPA on small block AVX2 */

#include "common.h"
#include "sha3.h"

/***********************************
*    USER CONFIGURABLE SETTINGS    *
***********************************/

/*!
\def QSC_RCS_AUTHENTICATED
* \brief Enables the AEAD cipher authentication mode.
* Unrem this flag to enable authenticated encryption for all modes.
*/
#if !defined(QSC_RCS_AUTHENTICATED)
#	define QSC_RCS_AUTHENTICATED
#endif

/*!
\def QSC_RCS_AUTH_KMACR12
* \brief Enables the reduced rounds KMAC-R12 implementation.
* Unrem this flag to enable the reduced rounds KMAC implementation.
*/
#if !defined(QSC_RCS_AUTH_KMACR12)
#	define QSC_RCS_AUTH_KMACR12
#endif

/*!
* \def QSC_RCS_AESNI_ENABLED
* \brief Enable the use of intrinsics and the AES-NI implementation.
* Just for testing, add the QSC_RCS_AESNI_ENABLED preprocessor definition and enable SIMD and AES-NI.
*/
#if !defined(QSC_RCS_AESNI_ENABLED)
#	define QSC_RCS_AESNI_ENABLED
#endif

/***********************************
*     RCS CONSTANTS AND SIZES      *
***********************************/

#if defined(QSC_RCS_AESNI_ENABLED)
#	include "intrinsics.h"
#	include <immintrin.h>
#endif

/*!
* \def QSC_RCS_BLOCK_SIZE
* \brief The internal block size in bytes, required by the encryption and decryption functions.
*/
#define QSC_RCS_BLOCK_SIZE 32

/*!
* \def QSC_RCS256_KEY_SIZE
* \brief The size in bytes of the RCS-256 input cipher-key.
*/
#define QSC_RCS256_KEY_SIZE 32

/*!
* \def QSC_RCS256_MAC_SIZE
* \brief The RCS-256 MAC code array length in bytes.
*/
#define QSC_RCS256_MAC_SIZE 32

/*!
* \def QSC_RCS512_KEY_SIZE
* \brief The size in bytes of the RCS-512 input cipher-key.
*/
#define QSC_RCS512_KEY_SIZE 64

/*!
* \def QSC_RCS512_MAC_SIZE
* \brief The RCS-512 MAC code array length in bytes.
*/
#define QSC_RCS512_MAC_SIZE 64

/*!
* \def QSC_RCS_NONCE_SIZE
* \brief The nonce size in bytes.
*/
#define QSC_RCS_NONCE_SIZE 32

/*! \enum rcs_cipher_type
* \brief The pre-defined cipher mode implementations
*/
typedef enum
{
	RCS256 = 1,	/*!< The RCS-256 cipher */
	RCS512 = 2,	/*!< The RCS-512 cipher */
} rcs_cipher_type;

/*!
* \struct qsc_rcs_keyparams
* \brief The key parameters structure containing key, nonce, and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the qsc_rcs_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
* The nonce is always QSC_RCS_BLOCK_SIZE in length.
*/
QSC_EXPORT_API typedef struct
{
	const uint8_t* key;					/*!< The input cipher key */
	size_t keylen;						/*!< The length in bytes of the cipher key */
	uint8_t* nonce;						/*!< The nonce or initialization vector */
	const uint8_t* info;				/*!< The information tweak */
	size_t infolen;						/*!< The length in bytes of the information tweak */
} qsc_rcs_keyparams;

/*!
* \struct qsc_rcs_state
* \brief The internal state structure containing the round-key array.
*/
QSC_EXPORT_API typedef struct
{
	rcs_cipher_type ctype;				/*!< The cipher type; RCS-256 or RCS-512 */
#if defined(QSC_RCS_AESNI_ENABLED)
	__m128i roundkeys[62];				/*!< The 128-bit integer round-key array */
#	if defined(QSC_SYSTEM_HAS_AVX512)
		__m512i roundkeysw[31];			/*!< The 512-bit integer round-key array */
#	endif
#else
	uint32_t roundkeys[248];			/*!< The round-keys 32-bit subkey array */
#endif
	size_t roundkeylen;					/*!< The round-key array length */
	size_t rounds;						/*!< The number of transformation rounds */
#if defined(QSC_RCS_KPA_AUTHENTICATION)
	qsc_kpa_state kstate;				/*!< The KPA state structure */
#else
	qsc_keccak_state kstate;			/*!< The keccak state structure */
#endif
	uint8_t nonce[QSC_RCS_NONCE_SIZE];	/*!< The nonce or initialization vector */
	uint64_t counter;					/*!< the processed bytes counter */
	bool encrypt;						/*!< the transformation mode; true for encryption */
} qsc_rcs_state;

/* public functions */

/**
* \brief Dispose of the RCS cipher state.
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
QSC_EXPORT_API void qsc_rcs_dispose(qsc_rcs_state* ctx);

/**
* \brief Initialize the state with the input cipher-key and optional info tweak.
*
* \param ctx: [struct] The cipher state structure
* \param keyparams: [const][struct] The secret input cipher-key and nonce structure
* \param encryption: Initialize the cipher for encryption, or false for decryption mode
*/
QSC_EXPORT_API void qsc_rcs_initialize(qsc_rcs_state* ctx, const qsc_rcs_keyparams* keyparams, bool encryption);

/**
* \brief Set the associated data string used in authenticating the message.
* The associated data may be packet header information, domain specific data, or a secret shared by a group.
* The associated data must be set after initialization, and before each transformation call.
* The data is erased after each call to the transform.
*
* \warning The cipher must be initialized before this function can be called
*
* \param ctx: [struct] The cipher state structure
* \param data: [const] The associated data array
* \param length: The associated data array length
*/
QSC_EXPORT_API void qsc_rcs_set_associated(qsc_rcs_state* ctx, const uint8_t* data, size_t length);

/**
* \brief Transform an array of bytes.
* In encryption mode, the input plain-text is encrypted and then an authentication MAC code is appended to the ciphertext.
* In decryption mode, the input cipher-text is authenticated internally and compared to the mac code appended to the cipher-text,
* if the codes to not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param ctx: [struct] The cipher state structure
* \param output: A pointer to the output array
* \param input: [const] A pointer to the input array
* \param length: The number of bytes to transform
*
* \return: Returns true if the cipher has been transformed the data successfully, false on failure
*/
QSC_EXPORT_API bool qsc_rcs_transform(qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/**
* \brief A multi-call transform for a large array of bytes, such as required by file encryption.
* This call can be used to transform and authenticate a very large array of bytes (+1GB).
* On the last call in the sequence, set the finalize parameter to true to complete authentication,
* and write the MAC code to the end of the output array in encryption mode,
* or compare to the embedded MAC code and authenticate in decryption mode.
* In encryption mode, the input plain-text is encrypted, then authenticated, and the MAC code is appended to the cipher-text.
* In decryption mode, the input cipher-text is authenticated internally and compared to the MAC code appended to the cipher-text,
* if the codes to not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param ctx: [struct] The cipher state structure
* \param output: A pointer to the output array
* \param input: [const] A pointer to the input array
* \param length: The number of bytes to transform
* \param finalize: Complete authentication on a stream if set to true
*
* \return: Returns true if the cipher has been transformed the data successfully, false on failure
*/
QSC_EXPORT_API bool qsc_rcs_extended_transform(qsc_rcs_state* ctx, uint8_t* output, const uint8_t* input, size_t length, bool finalize);

#endif
