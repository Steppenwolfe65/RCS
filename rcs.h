/* The GPL version 3 License (GPLv3)
* 
* Copyright (c) 2020 vtdev.com
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
* An implementation of the Rijndael-256 authenticated Cipher Stream.
* Written by John G. Underhill
* February 05, 2020
* Contact: develop@vtdev.com */

/*!
* \mainpage <b>The RCS cipher</b>
* \section intro_sec Welcome
* <p>The RCS (Rijndael-256 authenticated Cipher Stream) encryption functions, are a hybrid of the Rijndael-256 rounds function,
* and a cryptographically strong pseudo-random generator function (cSHAKE) used to expand the round-key array (the key-schedule). \n
* The cryptographic XOF, generates the round key array used by the Rijndael rounds function, enabling the safe addition of increased mixing rounds, 
* and replacing the differentially-weak native Rijndael key-schedule expansion function. \n
* The cipher increases the number of mixing rounds from 14 used by AES-256, to 22 used by RCS-256, twice the best known classical computer attack. \n
* The cipher also has a 512-bit key configuration, which uses 30 rounds of mixing. \n
* There are attacks now being proposed, that strongly indicate that larger key sizes will be necessary against future quantum-based attacks on symmetric ciphers.</p>
* 
* <p>The pseudo-random bytes generator used by this cipher is the Keccak cSHAKE extended output function (XOF).
* The cSHAKE XOF is implemented in 256 and 512-bit forms of those functions, correlating to the input cipher-key size.
* The cipher has two base variants; RCS256 and RCS512, the 256 variant using a 256-bit input key, and RCS512 using a 512-bit key.
* This change in key schedule expansion functions to the stronger Keccak based XOF function, can now can safely produce a larger round-key array,
* unlocking an increased number of mixing rounds, and preventing many serious forms of attack on the Rijndael-based ciphers.</p>
*
* <p>This is a 'tweakable cipher', the initialization parameters; rcs_keyparams, include an info parameter that can be used as a secondary user input.
* Internally, the info parameter is used to customize the cSHAKE output, using the cSHAKE 'name' parameter to pre-initialize the SHAKE state. 
* The info parameter can be tweaked, with a user defined string 'info' in an rcs_keyparams structure passed to the rcs_intitialize(state,keyparams,encrypt,mode). 
* This tweak can be used as a 'domain key', or to differentiate cipher-text output from other implementations, or as a secondary secret-key input.</p>
* 
* \section Authentication
* <p>RCS is an authenticated encryption with associated data (AEAD) stream cipher.
* It uses the hash-based key schedule extended form of Rijndael-256, wrapped in a segmented integer counter mode (CTR) for encryption.
* The cSHAKE key-schedule function also generates a key for the keyed hash-based MAC funtion; KMAC or HMAC, used to generate the authentication code, 
* which is appended to the cipher-text output of an encryption call.
* In decryption mode, before decryption is performed, an internal mac code is calculated, and compared to the code embedded in the cipher-text.
* If authentication fails, the cipher-text is not decrypted, and the rcs_transform(state,out,in,inlen) function returns a boolean false value.
* The rcs_set_associated(state,in,inlen) function can be used to add additional data to the MAC generators input, like packet-header data, or a custom code or counter.</p>

* \section Implementation
* This implementation has both a C reference code, and an implementation that uses the AES-NI instructions that are used in the AES and RCS cipher variants. \n
* The AES-NI implementation can be enabled by adding the RCS_AESNI_ENABLED constant to your preprocessor definitions. \n
* The implementation can be toggled from SHA3 to SHA2 HMAC authentication mode by adding the RCS_HMAC_EXTENSION to the pre-processor definitions. \n
* The RCS-256, RCS-512, known answer vectors are taken from the CEX++ cryptographic library <a href="https://github.com/Steppenwolfe65/CEX">The CEX++ Cryptographic Library</a>. \n
* See the documentation and the rcs_kat.h tests for usage examples.</p>
*
* \ section Links
* Towards post-quantum symmetric cryptography
* https://eprint.iacr.org/2019/553
* Towards Post-Quantum Secure Symmetric Cryptography: A Mathematical Perspective
* https://eprint.iacr.org/2019/1208
* 
*
* \author		John G. Underhill
* \version		1.0.0.0c
* \date			October 20, 2019
* \updated		February 05, 2020
* \contact:		develop@vtdev.com
* \copyright	GPL version 3 license (GPLv3)
*/

/**
* \file rcs.h
* \brief <b>RCS header definition</b> \n
* Rijndael-256 authenticated Cipher Stream.
*
* \author John Underhill
* \date February 05, 2020
*

* <b>RCS-256 encryption example</b> \n
* \code
* // external message, key, nonce, and custom-info arrays
* const size_t CST_LEN = 20;
* const size_t MSG_LEN = 200;
* uint8_t cust[CST_LEN] = {...};
* uint8_t key[RCS256_KEY_SIZE] = {...};
* uint8_t msg[MSG_LEN] = {...};
* uint8_t nonce[RCS_BLOCK_SIZE] = {...};
* ...
* uint8_t cpt[MSG_LEN + RCS256_MAC_LENGTH] = { 0 };
* rcs_state state;
* rcs_keyparams kp = { key, RCS256_KEY_SIZE, nonce, cust, CST_LEN };
* 
* // initialize the state
* rcs_initialize(&state, &kp, true, RCS256);
* // encrypt the message
* rcs_transform(&state, cpt, msg, MSG_LEN)
* \endcode
*
* <b>RCS-256 decryption example</b> \n
* \code
* // external cipher-text, key and custom-info arrays,
* // and cipher-text containing the encrypted plain-text and the mac-code
* uint8_t cpt[CPT_LEN] = { rcs_transform(k,p) }
* uint8_t key[RCS256_KEY_SIZE] = {...};
* uint8_t nonce[RCS_BLOCK_SIZE] = {...};
* uint8_t cust[CST_LEN] = {...};
* ...
* // subtract the mac-code length from the overall cipher-text length for the message size
* const size_t MSG_LEN = CPT_LEN - RCS256_MAC_LENGTH;
* uint8_t msg[MSG_LEN] = { 0 };
* rcs_keyparams kp = { key, RCS256_KEY_SIZE, nonce, cust, CST_LEN };
*
* // initialize the cipher state for decryption
* rcs_initialize(&state, &kp, false, RCS256);
*
* // authenticate and decrypt the cipher-text
* if (rcs256_transform(&state, msg, cpt, MSG_LEN) == false)
* {
*	// authentication has failed, do something..
* }
* \endcode
*
* \remarks
* To enable the AES-NI implementation, uncomment the definition in this file or add RCS_AESNI_ENABLED or add it to the compiler preprocessor definitions. \n
* To change the authentication function from the KMAC Keccak-based to the HMAC(SHA2) authentication MAC protocol,
* add the RCS_HMAC_EXTENSION flag to the preprocessor definitions.
*
* For usage examples, see rcs_kat.c. \n
*/

#ifndef QSC_RCS_H
#define QSC_RCS_H

#include "common.h"
#include "sha3.h"

/***********************************
*    USER CONFIGURABLE SETTINGS    *
***********************************/

/*!
\def RCS_AESNI_ENABLED
* Enable the use of intrinsics and the AES-NI implementation.
* Just for testing, add the RCS_AESNI_ENABLED preprocessor definition and enable SIMD and AES-NI.
*/
#ifndef RCS_AESNI_ENABLED
//#	define RCS_AESNI_ENABLED
#endif 

#ifdef RCS_AESNI_ENABLED
#	if defined(QSC_COMPILER_MSC)
#		include <intrin.h>
#		include <wmmintrin.h>
#	elif defined(QSC_COMPILER_GCC)
#		include <x86intrin.h>
#	endif
#endif

/***********************************
*     RCS CONSTANTS AND SIZES      *
***********************************/

/*! \enum cipher_mode
* The pre-defined cipher mode implementations
*/
typedef enum
{
	RCS256 = 1,	/*!< The RCS-256 cipher */
	RCS512 = 2,	/*!< The RCS-512 cipher */
} rcs_cipher_type;

/*!
\def RCS256_MAC_LENGTH
* The RCS-256 MAC code array length in bytes.
*/
#define RCS256_MAC_LENGTH 32

/*!
\def RCS512_MAC_LENGTH
* The RCS-512 MAC code array length in bytes.
*/
#define RCS512_MAC_LENGTH 64

/*!
\def RCS_BLOCK_SIZE
* The internal block size in bytes, required by the encryption and decryption functions.
*/
#define RCS_BLOCK_SIZE 32

/*!
\def RCS256_KEY_SIZE
* The size in bytes of the RCS-256 input cipher-key.
*/
#define RCS256_KEY_SIZE 32

/*!
\def RCS512_KEY_SIZE
* The size in bytes of the RCS-512 input cipher-key.
*/
#define RCS512_KEY_SIZE 64

/*!
\def RCS256_MAC_LENGTH
* The size of the RCS-256 mac code
*/
#define RCS256_MAC_LENGTH 32

/*!
\def RCS512_MAC_LENGTH
* The size of the RCS-512 mac code
*/
#define RCS512_MAC_LENGTH 64

/*! \struct rcs_keyparams
* The key parameters structure containing key, nonce, and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the rcs_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
* The nonce is always RCS_BLOCK_SIZE in length.
*/
typedef struct
{
	const uint8_t* key;				/*!< The input cipher key */
	size_t keylen;					/*!< The length in bytes of the cipher key */
	uint8_t* nonce;					/*!< The nonce or initialization vector */
	const uint8_t* info;			/*!< The information tweak */
	size_t infolen;					/*!< The length in bytes of the information tweak */
} rcs_keyparams;

/*! \struct rcs_state
* The internal state structure containing the round-key array.
*/
typedef struct
{
	rcs_cipher_type ctype;			/*!< The cipher type; RCS-256 or RCS-512 */
#if defined(RCS_AESNI_ENABLED)
	__m128i roundkeys[62];			/*!< The 128-bit integer round-key array */
#else
	uint32_t roundkeys[248];		/*!< The round-keys 32-bit subkey array */
#endif
	size_t roundkeylen;				/*!< The round-key array length */
	size_t rounds;					/*!< The number of transformation rounds */
	keccak_state kstate;			/*!< The keccak state structure */
	uint8_t* nonce;					/*!< The nonce or initialization vector */
	uint64_t counter;				/*!< the processed bytes counter */
	uint8_t mkey[64];				/*!< the mac generators key array */
	size_t mkeylen;					/*!< the mac key array length */
	const uint8_t* custom;			/*!< the customization array */
	size_t custlen;					/*!< the customization array length */
	uint8_t* aad;					/*!< the additional data array */
	size_t aadlen;					/*!< the additional data array length */
	bool encrypt;					/*!< the transformation mode; true for encryption */
} rcs_state;

/* public functions */

/**
* \brief Dispose of the RCS cipher state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys internal arrays allocated on the heap,
* and must be called before the state goes out of scope.
*
* \param state: [struct] The RCS state structure; contains internal state information
*/
void rcs_dispose(rcs_state* state);

/**
* \brief Initialize the state with the input cipher-key and optional info tweak.
*
* \param state: [struct] The rcs_state structure
* \param keyparams: The secret input cipher-key
* \param encryption: Initialize the cipher for encryption, or false for decryption mode
* \param ctype: Selects the cipher type, either RCS256 or RCS512
*/
void rcs_initialize(rcs_state* state, const rcs_keyparams* keyparams, bool encryption, rcs_cipher_type ctype);

/**
* \brief Set the associated data string used in authenticating the message.
* The associated data may be packet header information, domain specific data, or a secret shared by a group.
* The associated data must be set after initialization, and before each transformation call.
* The data is erased after each call to the transform.
*
* \warning The cipher must be initialized before this function can be called
*
* \param state: [struct] The RCS state structure; contains internal state information
* \param data: [const] The associated data array
* \param datalen: The associated data array length
*/
void rcs_set_associated(rcs_state* state, uint8_t* data, size_t datalen);

/**
* \brief Transform an array of bytes.
* In encryption mode, the input plain-text is encrypted and then an authentication MAC code is appended to the ciphertext.
* In decryption mode, the input cipher-text is authenticated internally and compared to the mac code appended to the cipher-text,
* if the codes to not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param state: [struct] The RCS state structure; contains internal state information
* \param keyparams: [struct] The RCS key parameters, includes the key, and optional AAD and user info arrays
* \param encrypt: The cipher encryption mode; true for encryption, false for decryption
*
* \return: Returns true if the cipher has been transformed the data successfully, false on failure
*/
bool rcs_transform(rcs_state* state, uint8_t* output, const uint8_t* input, size_t inputlen);

#endif
