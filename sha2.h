/**
* \file sha2.h
* \author John Underhill
* \date May 23, 2019
*
* \brief <b>SHA2 header definition</b> \n
* Contains the public api and documentation for SHA2 digests, HMAC and HKDF implementations.
*
* <b>SHA2-512 hash computation using long-form api</b> \n
* \code
* // external message array
* const size_t MSG_LEN = 200;
* uint8_t msg[200] = { ... };
* ...
*
* uint8_t otp[SHA2_512_HASH] = { 0 };
* sha512_state state;
* const size_t BLK_CNT = MSG_LEN / SHA3_512_RATE;
* size_t msgpos;
*
* msgpos = 0;
* clear8(otp, sizeof(otp));
*
* // initialize the SHA2 state
* sha512_initialize(&state);
*
* // process full blocks of message
* if (BLK_CNT != 0)
* {
*	sha512_blockupdate(&state, msg, BLK_CNT);
* 	msgpos += (SHA3_512_RATE * BLK_CNT);
* }
*
* // finalize the message
* sha512_finalize(&state, otp, msg + msgpos, MSG_LEN - msgpos);
* \endcode
*
*
* <b>HMAC-512 MAC code generation using long-form api</b> \n
* \code
*
* \endcode
*
* \remarks For usage examples, see sha3_kat.h. \n
*
* \ section Links
* NIST: The SHA-2 Standard http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf"
*
* Analysis of SIMD Applicability to SHA Algorithms https://software.intel.com/sites/default/files/m/b/9/b/aciicmez.pdf
*
* \remarks
* <p>The SHA2 and HMAC implementations use two different forms of api: short-form and long-form. \n
* The short-form api, which initializes the state, processes a message, and finalizes by producing output, all in a single function call,
* for example; sha2_compute512(uint8_t* output, const uint8_t* message, size_t msglen),
* the entire message array is processed and the hash code is written to the output array. \n
* The long-form api uses an initialization call to prepare the state, a blockupdate call if the message is longer than a single message block,
* and the finalize call, which finalizes the state and generates a hash or mac-code. \n
* The HKDF key derivation functions HKDF(HMAC(SHA2-256/512)), use only the short-form api, single-call functions, to generate pseudo-random to an output array. \n
* Each of the function families (SHA2, HMAC, HKDF), have a corresponding set of reference constants associated with that member, example;
* HKDF_256_KEY is the minimum expected HKDF-256 key size in bytes, HMAC_512_MAC is the minimum size of the HMAC-512 output mac-code output array,
* and SHA2_512_RATE is the SHA2-512 message absorbtion rate.</p>
*
* For additional usage examples, see sha2_kat.h
*
*/

#ifndef QSC_SHA2_H
#define QSC_SHA2_H

#include "common.h"

/*!
\def SHA2_SHANI_ENABLED
* Enables the SHA2 permutation intrinsics.
* For testing only; add this flag to your preprocessor defintions to enable SHA-NI intrinsics.
*/
#ifndef SHA2_SHANI_ENABLED
//#	define SHA2_SHANI_ENABLED
#endif

/*!
\def HKDF_256_KEY
* The HKDF-256 key size in bytes
*/
#define HKDF_256_KEY 32

/*!
\def HKDF_512_KEY
* The HKDF-512 key size in bytes
*/
#define HKDF_512_KEY 64

/*!
\def HMAC_256_KEY
* The recommended HMAC(SHA2-256) key size, minimum is 32 bytes
*/
#define HMAC_256_KEY 64

/*!
\def HMAC_512_KEY
* The recommended HMAC(SHA2-512) key size minimum is 64 bytes
*/
#define HMAC_512_KEY 128

/*!
\def HMAC_256_MAC
* The HMAC-256 mac-code size in bytes
*/
#define HMAC_256_MAC 32

/*!
\def HMAC_512_MAC
* The HMAC-512 mac-code size in bytes
*/
#define HMAC_512_MAC 64

/*!
\def SHA2_256_HASH
* The SHA2-256 hash size in bytes
*/
#define SHA2_256_HASH 32

/*!
\def SHA2_384_HASH
* The SHA2-384 hash size in bytes
*/
#define SHA2_384_HASH 48

/*!
\def SHA2_512_HASH
* The SHA2-512 hash size in bytes
*/
#define SHA2_512_HASH 64

/*!
\def SHA2_256_ROUNDS
* the number of rounds in the compact SHA2-256 permutation
*/
#define SHA2_256_ROUNDS 64

/*!
\def SHA2_384_ROUNDS
* the number of rounds in the compact SHA2-384 permutation
*/
#define SHA2_384_ROUNDS 80

/*!
\def SHA2_512_ROUNDS
* the number of rounds in the compact SHA2-512 permutation
*/
#define SHA2_512_ROUNDS 80

/*!
\def SHA2_256_RATE
* The SHA-256 byte absorption rate
*/
#define SHA2_256_RATE 64

/*!
\def SHA2_384_RATE
* The SHA2-384 byte absorption rate
*/
#define SHA2_384_RATE 128

/*!
\def SHA2_512_RATE
* The SHA2-512 byte absorption rate
*/
#define SHA2_512_RATE 128

/*!
\def SHA2_256_STATESIZE
* The SHA2-256 state array size
*/
#define SHA2_STATE_SIZE 8

/* sha2-256 */

/*! \struct sha256_state
* The SHA2-256 digest state array
*/
typedef struct
{
	uint32_t state[8];
	uint64_t t;
} sha256_state;

/**
* \brief Process a message with SHA2-256 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
void sha2_compute256(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Update SHA2-256 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a multiple of 64-byte block lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message: [const] The input message byte array
* \param nblocks: The number of rate sized blocks to process
*/
void sha256_blockupdate(sha256_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief Finalize the message state and returns the hash value in output.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Absorb the last block of message and creates the hash value. \n
* Produces a 32 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
void sha256_finalize(sha256_state* state, uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Initializes a SHA2-256 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
*
* \param state: [struct] The function state
*/
void sha256_initialize(sha256_state* state);

/**
* \brief The SHA2-256 permution function.
* Internal function: called by protocol hash and generation functions, or in the construction of other external protocols.
* Permutes the state array.
*
* \param output: The function state; must be initialized
* \param input: [const] The input message byte array
*/
void sha256_permute(uint32_t* output, const uint8_t* input);

/* sha2-384 */

/*! \struct sha384_state
* The SHA2-384 digest state array
*/
typedef struct
{
	uint64_t state[8];
	uint64_t t[2];
} sha384_state;

/**
* \brief Process a message with SHA2-384 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 48 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen The number of message bytes to process
*/
void sha2_compute384(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Update SHA2-384 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a multiple of 128-byte block sized lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message:[const] The input message byte array
* \param nblocks The number of rate sized blocks to process
*/
void sha384_blockupdate(sha384_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief Finalize the message state and returns the SHA2-384 hash value in output.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Absorb the last block of message and creates the hash value. \n
* Produces a 48 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
void sha384_finalize(sha384_state* state, uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Initializes a SHA2-384 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
*
* \param state: [struct] The function state
*/
void sha384_initialize(sha384_state* state);

/**
* \brief The SHA2-384 permution function.
* Internal function: called by protocol hash and generation functions, or in the construction of other external protocols.
* Permutes the state array.
*
* \param state: The function state; must be initialized
* \param message: [const] The input message byte array
*/
void sha384_permute(uint64_t* output, const uint8_t* input);

/* sha2-512 */

/*! \struct sha512_state
* The SHA2-512 digest state array
*/
typedef struct
{
	uint64_t state[8];
	uint64_t t[2];
} sha512_state;

/**
* \brief Process a message with SHA2-512 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 64 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen The number of message bytes to process
*/
void sha2_compute512(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Update SHA2-512 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a multiple of 128-byte block sized lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message:[const] The input message byte array
* \param nblocks The number of rate sized blocks to process
*/
void sha512_blockupdate(sha512_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief Finalize the message state and returns the SHA2-512 hash value in output.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Absorb the last block of message and creates the hash value. \n
* Produces a 64 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
void sha512_finalize(sha512_state* state, uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Initializes a SHA2-512 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
*
* \param state: [struct] The function state
*/
void sha512_initialize(sha512_state* state);

/**
* \brief The SHA2-512 permution function.
* Internal function: called by protocol hash and generation functions, or in the construction of other external protocols.
* Permutes the state array.
*
* \param state: The function state; must be initialized
* \param message: [const] The input message byte array
*/
void sha512_permute(uint64_t* output, const uint8_t* input);

/* hmac-256 */

/*! \struct hmac256_state
* The HMAC(SHA2-256) state array
*/
typedef struct
{
	sha256_state pstate;
	uint8_t ipad[SHA2_256_RATE];
	uint8_t opad[SHA2_256_RATE];
} hmac256_state;

/**
* \brief Process a message with HMAC(SHA2-256) and returns the hash code in the output byte array.
* Short form api: processes the key and complete message, and generates the MAC code with a single call.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
void hmac256_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen);

/**
* \brief Update HMAC-256 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a multiple of 64-byte block lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message: [const] The input message byte array
* \param nblocks: The number of rate sized blocks to process
*/
void hmac256_blockupdate(hmac256_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief Finalize the HMAC-256 message state and return the hash value in output.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Absorb the last block of message and creates the hash value. \n
* Produces a 32 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
void hmac256_finalize(hmac256_state* state, uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Initializes a HMAC-256 state structure with a key, must be called before message processing.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
*
* \param state: [struct] The function state
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
void hmac256_initialize(hmac256_state* state, const uint8_t* key, size_t keylen);

/* hmac-512 */

/*! \struct hmac512_state
* The HMAC(SHA2-512) state array
*/
typedef struct
{
	sha512_state pstate;
	uint8_t ipad[SHA2_512_RATE];
	uint8_t opad[SHA2_512_RATE];
} hmac512_state;

/**
* \brief Process a message with SHA2-512 and returns the hash code in the output byte array.
* Short form api: processes the key and complete message, and generates the MAC code with a single call.
*
* \warning The output array must be at least 128 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
void hmac512_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen);

/**
* \brief Update HMAC-512 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a multiple of 128-byte block lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message: [const] The input message byte array
* \param nblocks: The number of rate sized blocks to process
*/
void hmac512_blockupdate(hmac512_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief Finalize the HMAC-512 message state and return the hash value in output.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Absorb the last block of message and creates the hash value. \n
* Produces a 64 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
void hmac512_finalize(hmac512_state* state, uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Initializes a HMAC-512 state structure with a key, must be called before message processing.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
*
* \param state: [struct] The function state
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
void hmac512_initialize(hmac512_state* state, const uint8_t* key, size_t keylen);

/* hkdf */

/**
* \brief Initialize and instance of HKDF(HMAC(SHA2-256)), and output an array of pseudo-random.
* Short form api: initializes with the key and user info, and generates the output pseudo-random with a single call.
*
* \param output: The output pseudo-random byte array
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param info: [const] The info array
* \param infolen: The info array length
*/
void hkdf256_expand(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen);

/**
* \brief Extract a key from a combined key and salt input using HMAC(SHA2-256).
*
* \param output: The output pseudo-random byte array
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param salt: [const] The salt array
* \param saltlen: The salt array length
*/
void hkdf256_extract(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen);

/**
* \brief Initialize and instance of HKDF(HMAC(SHA2-512)), and output an array of pseudo-random.
* Short form api: initializes with the key and user info, and generates the output pseudo-random with a single call.
*
* \param output: The output pseudo-random byte array
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param info: [const] The info array
* \param infolen: The info array length
*/
void hkdf512_expand(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen);

/**
* \brief Extract a key from a combined key and salt input using HMAC(SHA2-512).
*
* \param output: The output pseudo-random byte array
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param salt: [const] The salt array
* \param saltlen: The salt array length
*/
void hkdf512_extract(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen);

#endif

