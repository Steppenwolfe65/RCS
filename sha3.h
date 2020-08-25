/**
* \file sha3.h
* \author John Underhill
* \date October 27, 2019
* \updated February 5, 2020
*
* \brief <b>SHA3 header definition</b> \n
* Contains the public api and documentation for SHA3 digest, SHAKE, cSHAKE, and KMAC implementations.
*
* <b>Usage Examples</b> \n
*
* <b>SHA3-512 hash computation using long-form api</b> \n
* \code
* // external message array
* const size_t MSG_LEN = 200;
* uint8_t msg[MSG_LEN] = {...};
* ...
*
* uint8_t hash[SHA3_512_HASH] = { 0 };
* const size_t BLK_CNT = MSG_LEN / SHA3_512_RATE;
* size_t msgpos;
*
* msgpos = 0;
* // initialize the state to zeroes
* clear64(state.state, SHA3_STATE_SIZE);
*
* // process full blocks of message
* if (BLK_CNT != 0)
* {
* 	sha3_blockupdate(&state, SHA3_512_RATE, msg, BLK_CNT);
* 	msgpos += (SHA3_512_RATE * BLK_CNT);
* }
*
* // finalize the message and generate the hash
* sha3_finalize(&state, SHA3_512_RATE, msg + msgpos, MSG_LEN - msgpos, hash);
*
* \endcode
*
* <b>KMAC-512 MAC code generation using long-form api</b> \n
* \code
* // external message and key arrays
* const size_t MSG_LEN = 200;
* uint8_t msg[MSG_LEN] = {...};
* uint8_t key[KMAC_512_KEY] = {...};
* uint8_t cust[...] = {...};
*
* uint8_t code[KMAC_512_MAC] = { 0 };
* size_t BLKCNT = MSG_LEN / KMAC_512_RATE;
* size_t msgpos;
*
* msgpos = 0;
* // initialize the state to zeroes
* clear64(state.state, KMAC_STATE_SIZE);
*
* // initialize the state with the key and optional custom array
* kmac512_initialize(key, sizeof(key), cust, sizeof(cust));
*
* // process full blocks of message
* if (BLKCNT != 0)
* {
* 	kmac512_blockupdate(&state, msg, BLKCNT);
* 	msgpos += (KMAC_512_RATE * BLKCNT);
* }
*
* // finalize the message and generate the hash
* kmac512_finalize(&state, code, sizeof(code), msg + msgpos, MSG_LEN - msgpos);
*
* \endcode
*
* <b>cSHAKE-512 pseudo-random generation using long-form api</b> \n
* \code
*
* uint8_t output[SHAKE_512_RATE] = { 0 };
* uint8_t key[KMAC_512_KEY] = {...};
* uint8_t cust[...] = {...};
* uint8_t name[...] = {...};
* keccak_state state;
*
* // initialize the state to zeroes
* clear64(state.state, SHAKE_STATE_SIZE);
*
* // initialize cSHAKE with the key and optional name and custom arrays
* cshake512_initialize(&state, key, sizeof(key), name, sizeof(name), cust, sizeof(cust));
*
* // generate one block of pseudo-random
* cshake512_squeezeblocks(&state, output, 1);
* \endcode
*
* \remarks
* <p>The SHA3, SHAKE, cSHAKE, and KMAC implementations all share two forms of api: short-form and long-form. \n
* The short-form api, which initializes the state, processes a message, and finalizes by producing output, all in a single function call,
* for example; sha3_compute512(uint8_t* output, const uint8_t* message, size_t msglen),
* the entire message array is processed and the hash code is written to the output array. \n
* The long-form api uses an initialization call to prepare the state, a blockupdate call if the message is longer than a single message block,
* and the finalize call, which finalizes the state and generates a hash, mac-code, or an array of pseudo-random. \n
* Each of the function families (SHA3, SHAKE, KMAC), have a corresponding set of reference constants associated with that member, example;
* SHAKE_256_KEY is the minimum expected SHAKE-256 key size in bytes, KMAC_512_MAC is the minimum size of the KMAC-512 output mac-code output array,
* and SHA3_512_RATE is the SHA3-512 message absorbtion rate.</p>
*
* For additional usage examples, see sha3_kat.h. \n
*
* \section Links
* NIST: SHA3 Fips202 http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
* NIST: SP800-185 http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pd
* NIST: SHA3 Keccak Submission http://keccak.noekeon.org/Keccak-submission-3.pdf
* NIST: SHA3 Keccak Slides http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf
* NIST: SHA3 Third-Round Report http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf
* Team Keccak: Specifications summary https://keccak.team/keccak_specs_summary.html
*
* \remarks
* <p>The SHA3, SHAKE, cSHAKE, and KMAC implementations all share two forms of api: short-form and long-form. \n
* The short-form api, which initializes the state, processes a message, and finalizes by producing output, all in a single function call,
* for example; sha3_compute512(uint8_t* output, const uint8_t* message, size_t msglen),
* the entire message array is processed and the hash code is written to the output array. \n
* The long-form api uses an initialization call to prepare the state, a blockupdate call if the message is longer than a single message block,
* and the finalize call, which finalizes the state and generates a hash, mac-code, or an array of pseudo-random. \n
* Each of the function families (SHA3, SHAKE, cSHAKE, KMAC), have a corresponding set of reference constants associated with that member, example;
* SHAKE_256_KEY is the expected KMAC 256 key size in bytes, , SHA3_512_RATE is the SHA3-512 absorbtion rate (internal block size).</p>
*
* For additional usage examples, see sha3_kat.h
*
*/

#ifndef QSC_SHA3_H
#define QSC_SHA3_H

#include <stdint.h>

/*!
\def KECCAK_PERMUTATION_ROUNDS
* the number of rounds in the compact keccak permutation
*/
#define KECCAK_PERMUTATION_ROUNDS 24

/*!
\def KECCAK_COMPACT_PERMUTATION
* define to use the compact form of the keccak permutation function
* if undefined, functions use the constant time expanded keccak permutation
*/
//#define KECCAK_COMPACT_PERMUTATION

/*!
\def KMAC_DOMAIN_ID
* The KMAC function domain code
*/
#define KMAC_DOMAIN_ID 0x04;

/*!
\def KMAC_256_KEY
* The KMAC-256 key size in bytes
*/
#define KMAC_256_KEY 32

/*!
\def KMAC_512_KEY
* The KMAC-512 key size in bytes
*/
#define KMAC_512_KEY 64

/*!
\def KMAC_256_MAC
* The KMAC-256 default MAC code size in bytes
*/
#define KMAC_256_MAC 32

/*!
\def KMAC_512_MAC
* The KMAC-512 default MAC code size in bytes
*/
#define KMAC_512_MAC 64

/*!
\def KMAC_128_RATE
* The KMAC-128 byte absorption rate
*/
#define KMAC_128_RATE 168

/*!
\def KMAC_256_RATE
* The KMAC-256 byte absorption rate
*/
#define KMAC_256_RATE 136

/*!
\def KMAC_512_RATE
* The KMAC-512 byte absorption rate
*/
#define KMAC_512_RATE 72

/*!
\def KMAC_STATE_SIZE
* The Keccak KMAC uint64 state array size
*/
#define KMAC_STATE_SIZE 25

/*!
\def SHA3_DOMAIN_ID
* The SHA3 function domain code
*/
#define SHA3_DOMAIN_ID 0x06

/*!
\def SHA3_256_HASH
* The SHA-256 hash size in bytes
*/
#define SHA3_256_HASH 32

/*!
\def SHA3_512_HASH
* The SHA-512 hash size in bytes
*/
#define SHA3_512_HASH 64

/*!
\def SHA3_256_RATE
* The SHA-256 byte absorption rate
*/
#define SHA3_256_RATE 136

/*!
\def SHA3_512_RATE
* The SHA-512 byte absorption rate
*/
#define SHA3_512_RATE 72

/*!
\def SHA3_STATE_SIZE
* The Keccak SHA3 uint64 state array size
*/
#define SHA3_STATE_SIZE 25

/*!
\def SHA3_STATE_BYTE
* The Keccak SHA3 state size in bytes
*/
#define SHA3_STATE_BYTE 200

/*!
\def CSHAKE_DOMAIN_ID
* The cSHAKE function domain code
*/
#define CSHAKE_DOMAIN_ID 0x04

/*!
\def CSHAKE_256_KEY
* The CSHAKE-256 key size in bytes
*/
#define CSHAKE_256_KEY 32

/*!
\def CSHAKE_512_KEY
* The CSHAKE-512 key size in bytes
*/
#define CSHAKE_512_KEY 64

/*!
\def CSHAKE_128_RATE
* The cSHAKE-128 byte absorption rate
*/
#define CSHAKE_128_RATE 168

/*!
\def CSHAKE_256_RATE
* The cSHAKE-256 byte absorption rate
*/
#define CSHAKE_256_RATE 136

/*!
\def CSHAKE_512_RATE
* The cSHAKE-512 byte absorption rate
*/
#define CSHAKE_512_RATE 72

/*!
\def SHAKE_DOMAIN_ID
* The function domain code
*/
#define SHAKE_DOMAIN_ID 0x1F

/*!
\def SHAKE_256_KEY
* The SHAKE-256 key size in bytes
*/
#define CSHAKE_256_KEY 32

/*!
\def SHAKE_512_KEY
* The SHAKE-512 key size in bytes
*/
#define SHAKE512_KEY 64

/*!
\def SHAKE_128_RATE
* The SHAKE-128 byte absorption rate
*/
#define SHAKE_128_RATE 168

/*!
\def SHAKE_256_RATE
* The SHAKE-256 byte absorption rate
*/
#define SHAKE_256_RATE 136

/*!
\def SHAKE_512_RATE
* The SHAKE-512 byte absorption rate
*/
#define SHAKE_512_RATE 72

/*!
\def SHAKE_STATE_SIZE
* The Keccak SHAKE uint64 state array size
*/
#define SHAKE_STATE_SIZE 25

/*! \struct keccak_state
* The Keccak state array; state array must be initialized by the caller
*/
typedef struct
{
	uint64_t state[SHA3_STATE_SIZE];
} keccak_state;

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
void sha3_compute256(uint8_t* output, const uint8_t* message, size_t msglen);

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
void sha3_compute512(uint8_t* output, const uint8_t* message, size_t msglen);

/**
* \brief Update SHA3 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs (rate) block sized lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption, in bytes
* \param message: [const] The input message byte array
* \param nblocks: The number of rate sized blocks to process
*/
void sha3_blockupdate(keccak_state* state, size_t rate, const uint8_t* message, size_t nblocks);

/**
* \brief Finalize the message state and returns the hash value in output.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Absorb the last block of message and create the hash value. \n
* Produces a 32 byte output code using SHA3_256_RATE, 64 bytes with SHA3_512_RATE.
*
* \warning The output array must be sized correctly corresponding to the absorbtion rate ((200 - rate) / 2). \n
* Finalizes the message state, can not be used in consecutive calls.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption, in bytes
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
* \param output: The output byte array; receives the hash code
*/
void sha3_finalize(keccak_state* state, size_t rate, const uint8_t* message, size_t msglen, uint8_t* output);

/**
* \brief Initializes a SHA3 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
*
* \param state: [struct] The function * \param state: [struct ref] A reference to the keccak state; must be initialized
*/
void sha3_initialize(keccak_state* state);

/**
* \brief The Keccak permute function.
* Internal function: Permutes the state array, can be used in external constrictions.
*
* \param state: [struct] The function state; must be initialized
*/
void keccak_permute(uint64_t* state);

/* shake */

/**
* \brief Key a SHAKE-128 instance, and generate an array of pseudo-random bytes.
* Short form api: processes the key and generates the pseudo-random output with a single call.
*
* \warning The output array length must not be zero.
*
* \param output: The output byte array
* \param outputlen: The number of output bytes to generate
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
*/
void shake128_compute(uint8_t* output, size_t outputlen, const uint8_t* key, size_t keylen);

/**
* \brief The SHAKE-128 initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Absorb and finalize an input key byte array.
*
* \warning Finalizes the key state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
*/
void shake128_initialize(keccak_state* state, const uint8_t* key, size_t keylen);

/**
* \brief The SHAKE-128 squeeze function.
* Long form api: must be used in conjunction with the initialize function.
* Permutes and extracts the state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
*/
void shake128_squeezeblocks(keccak_state* state, uint8_t* output, size_t nblocks);

/**
* \brief Key a SHAKE-256 instance, and generate an array of pseudo-random bytes.
* Short form api: processes the key and generates the pseudo-random output with a single call.
*
* \warning The output array length must not be zero.
*
* \param output: The output byte array
* \param outputlen: The number of output bytes to generate
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
*/
void shake256_compute(uint8_t* output, size_t outputlen, const uint8_t* key, size_t keylen);

/**
* \brief The SHAKE-256 initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Absorb and finalize an input key byte array.
*
* \warning Finalizes the key state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
*/
void shake256_initialize(keccak_state* state, const uint8_t* key, size_t keylen);

/**
* \brief The SHAKE-256 squeeze function.
* Long form api: must be used in conjunction with the initialize function.
* Permutes and extracts the state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
*/
void shake256_squeezeblocks(keccak_state* state, uint8_t* output, size_t nblocks);

/**
* \brief Key a SHAKE-512 instance, and generate an array of pseudo-random bytes.
* Short form api: processes the key and generates the pseudo-random output with a single call.
*
* \warning The output array length must not be zero.
*
* \param output: The output byte array
* \param outputlen: The number of output bytes to generate
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
*/
void shake512_compute(uint8_t* output, size_t outputlen, const uint8_t* key, size_t keylen);

/**
* \brief The SHAKE-512 initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Absorb and finalize an input key byte array.
*
* \warning Finalizes the key state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
*/
void shake512_initialize(keccak_state* state, const uint8_t* key, size_t keylen);

/**
* \brief The SHAKE-512 squeeze function.
* Long form api: must be used in conjunction with the initialize function.
* Permutes and extracts the state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
*/
void shake512_squeezeblocks(keccak_state* state, uint8_t* output, size_t nblocks);

/* cshake */

/**
* \brief Key a cSHAKE-128 instance and generate pseudo-random output.
* Short form api: processes the key, name, and custom inputs and generates the pseudo-random output with a single call.
* Permutes and extracts the state to an output byte array..
*
* \param output: The output byte array
* \param outputlen: The number of output bytes to generate
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
* \param name: The function name string
* \param namelen: The byte length of the function name
* \param custom: The customization string
* \param customlen: The byte length of the customization string
*/
void cshake128_compute(uint8_t* output, size_t outputlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen);

/**
* \brief The cSHAKE-128 initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Initialize the name and customization strings into the state.
*
* \warning State must be initialized (and zeroed) by the caller.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
* \param name: The function name string
* \param namelen: The byte length of the function name
* \param custom: The customization string
* \param customlen: The byte length of the customization string
*/
void cshake128_initialize(keccak_state* state, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen);

/**
* \brief The cSHAKE-128 squeeze function.
* Long form api: must be used in conjunction with the initialize function.
* Permutes and extracts blocks of state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
*/
void cshake128_squeezeblocks(keccak_state* state, uint8_t* output, size_t nblocks);

/**
* \brief The cSHAKE-128 update function.
* Long form api: must be used in conjunction with the initialize and squeezeblocks functions.
* Absorb and finalize an input key directly into the state.
*
* \warning Finalizes the key state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
*/
void cshake128_update(keccak_state* state, const uint8_t* key, size_t keylen);

/**
* \brief Key a cSHAKE-256 instance and generate pseudo-random output.
* Short form api: processes the key, name, and custom inputs and generates the pseudo-random output with a single call.
* Permutes and extracts the state to an output byte array.
*
* \param output: The output byte array
* \param outputlen: The number of output bytes to generate
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
* \param name: The function name string
* \param namelen: The byte length of the function name
* \param custom: The customization string
* \param customlen: The byte length of the customization string
*/
void cshake256_compute(uint8_t* output, size_t outputlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen);

/**
* \brief The cSHAKE-256 initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Absorb and finalize an input key directly into the state.
*
* \warning Finalizes the key state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
* \param name: The function name string
* \param namelen: The byte length of the function name
* \param custom: The customization string
* \param customlen: The byte length of the customization string
*/
void cshake256_initialize(keccak_state* state, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen);

/**
* \brief The cSHAKE-256 update function.
* Long form api: must be used in conjunction with the initialize and squeezeblocks functions.
* Absorb and finalize an input key directly into the state.
*
* \warning Finalizes the key state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
*/
void cshake256_update(keccak_state* state, const uint8_t* key, size_t keylen);

/**
* \brief The cSHAKE-256 squeeze function.
* Long form api: must be used in conjunction with the initialize function.
* Permutes and extracts blocks of state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
*/
void cshake256_squeezeblocks(keccak_state* state, uint8_t* output, size_t nblocks);

/**
* \brief Key a cSHAKE-512 instance and generate pseudo-random output.
* Short form api: processes the key, name, and custom inputs and generates the pseudo-random output with a single call.
* Permutes and extracts the state to an output byte array.
*
* \param output: The output byte array
* \param outputlen: The number of output bytes to generate
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
* \param name: The function name string
* \param namelen: The byte length of the function name
* \param custom: The customization string
* \param customlen: The byte length of the customization string
*/
void cshake512_compute(uint8_t* output, size_t outputlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen);

/**
* \brief The cSHAKE-512 initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Absorb and finalize an input key directly into the state.
*
* \warning Finalizes the key state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
* \param name: The function name string
* \param namelen: The byte length of the function name
* \param custom: The customization string
* \param customlen: The byte length of the customization string
*/
void cshake512_initialize(keccak_state* state, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t customlen);

/**
* \brief The cSHAKE-512 update function.
* Long form api: must be used in conjunction with the initialize and squeezeblocks functions.
* Absorb and finalize an input key directly into the state.
*
* \warning Finalizes the key state, should not be used in consecutive calls. \n
* State must be initialized (and zeroed) by the caller.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
*/
void cshake512_update(keccak_state* state, const uint8_t* key, size_t keylen);

/**
* \brief The cSHAKE-512 squeeze function.
* Long form api: must be used in conjunction with the initialize function.
* Permutes and extracts blocks of state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
*/
void cshake512_squeezeblocks(keccak_state* state, uint8_t* output, size_t nblocks);

/* kmac */

/**
* \brief Key a KMAC-128 instance and generate a MAC code.
* Short form api: processes the key and custom inputs and generates the MAC code with a single call.
* Key the MAC generator process a message and output the MAC code.
*
* \param output: The mac code byte array
* \param outputlen: The number of mac code bytes to generate
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: The customization string
* \param customlen: The byte length of the customization string
* \param name: The function name string
* \param namelen: The byte length of the function name
*/
void kmac128_compute(uint8_t* output, size_t outputlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen, const uint8_t* name, size_t namelen);

/**
* \brief The KMAC-128 block update function.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Update the state with full blocks of message data.
*
* \warning kmac128_initialize must be called before this function to key and initialize the state. \n
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param message: [const] The message input byte array
* \param nblocks: The number of message byte blocks to process
*/
void kmac128_blockupdate(keccak_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief The KMAC-128 finalize function.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Final processing and calculation of the MAC code.
*
* \warning kmac128_initialize must be called before this function to key and initialize the state. \n
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param output: The output byte array
* \param outputlen: The number of bytes to extract
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
void kmac128_finalize(keccak_state* state, uint8_t* output, size_t outputlen, const uint8_t* message, size_t msglen);

/**
* \brief Initialize a KMAC-128 instance.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
* Key the MAC generator and initialize the internal state.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: The customization string
* \param customlen: The byte length of the customization string
* \param name: The function name string
* \param namelen: The byte length of the function name
*/
void kmac128_initialize(keccak_state* state, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen, const uint8_t* name, size_t namelen);

/**
* \brief Key a KMAC-256 instance and generate a MAC code.
* Short form api: processes the key and custom inputs and generates the MAC code with a single call.
* Key the MAC generator process a message and output the MAC code.
*
* \param output: The mac code byte array
* \param outputlen: The number of mac code bytes to generate
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: The customization string
* \param customlen: The byte length of the customization string
* \param name: The function name string
* \param namelen: The byte length of the function name
*/
void kmac256_compute(uint8_t* output, size_t outputlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen, const uint8_t* name, size_t namelen);

/**
* \brief The KMAC-256 block update function.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Update the state with full blocks of message data.
*
* \warning kmac256_initialize must be called before this function to key and initialize the state. \n
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param message: [const] The message input byte array
* \param nblocks: The number of message byte blocks to process
*/
void kmac256_blockupdate(keccak_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief The KMAC-256 finalize function.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Final processing and calculation of the MAC code.
*
* \warning kmac256_initialize must be called before this function to key and initialize the state. \n
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param output: The output byte array
* \param outputlen: The number of bytes to extract
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
void kmac256_finalize(keccak_state* state, uint8_t* output, size_t outputlen, const uint8_t* message, size_t msglen);

/**
* \brief Initialize a KMAC-256 instance.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
* Key the MAC generator and initialize the internal state.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: The customization string
* \param customlen: The byte length of the customization string
* \param name: The function name string
* \param namelen: The byte length of the function name
*/
void kmac256_initialize(keccak_state* state, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen, const uint8_t* name, size_t namelen);

/**
* \brief Key a KMAC-512 instance and generate a MAC code.
* Short form api: processes the key and custom inputs and generates the MAC code with a single call.
* Key the MAC generator process a message and output the MAC code.
*
* \param output: The mac code byte array
* \param outputlen: The number of mac code bytes to generate
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: The customization string
* \param customlen: The byte length of the customization string
* \param name: The function name string
* \param namelen: The byte length of the function name
*/
void kmac512_compute(uint8_t* output, size_t outputlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen, const uint8_t* name, size_t namelen);

/**
* \brief The KMAC-512 block update function.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Update the state with full blocks of message data.
*
* \warning kmac512_initialize must be called before this function to key and initialize the state. \n
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param message: [const] The message input byte array
* \param nblocks: The number of message byte blocks to process
*/
void kmac512_blockupdate(keccak_state* state, const uint8_t* message, size_t nblocks);

/**
* \brief The KMAC-512 finalize function.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Final processing and calculation of the MAC code.
*
* \warning kmac512_initialize must be called before this function to key and initialize the state. \n
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param output: The output byte array
* \param outputlen: The number of bytes to extract
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
void kmac512_finalize(keccak_state* state, uint8_t* output, size_t outputlen, const uint8_t* message, size_t msglen);

/**
* \brief Initialize a KMAC-512 instance.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
* Key the MAC generator and initialize the internal state.
*
* \param state: [struct ref] A reference to the keccak state; must be initialized
* \param key: The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: The customization string
* \param customlen: The byte length of the customization string
* \param name: The function name string
* \param namelen: The byte length of the function name
*/
void kmac512_initialize(keccak_state* state, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t customlen, const uint8_t* name, size_t namelen);

#endif
