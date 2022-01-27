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

#ifndef QSC_INTUTILS_H
#define QSC_INTUTILS_H

#include "common.h"
#include "intrinsics.h"

/*
* \file intutils.h
* \brief This file contains common integer functions
*/

/**
* \brief Compares two byte 8-bit integers for equality
*
* \param a: [const] The first array to compare
* \param b: [const] The second array to compare
* \param length: The number of bytes to compare
* \return Returns true for equal values
*/
QSC_EXPORT_API bool qsc_intutils_are_equal8(const uint8_t* a, const uint8_t* b, size_t length);

/**
* \brief Convert an 8-bit integer array to a 16-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 16-bit big endian integer
*/
QSC_EXPORT_API uint16_t qsc_intutils_be8to16(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 32-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 32-bit big endian integer
*/
QSC_EXPORT_API uint32_t qsc_intutils_be8to32(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 64-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 64-bit big endian integer
*/
QSC_EXPORT_API uint64_t qsc_intutils_be8to64(const uint8_t* input);

/**
* \brief Convert a 16-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 16-bit integer
*/
QSC_EXPORT_API void qsc_intutils_be16to8(uint8_t* output, uint16_t value);

/**
* \brief Convert a 32-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 32-bit integer
*/
QSC_EXPORT_API void qsc_intutils_be32to8(uint8_t* output, uint32_t value);

/**
* \brief Convert a 64-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 64-bit integer
*/
QSC_EXPORT_API void qsc_intutils_be64to8(uint8_t* output, uint64_t value);

/**
* \brief Increment an 8-bit integer array as a segmented big-endian integer
*
* \param output: The destination integer 8-bit array
* \param outlen: The length of the output counter array
*/
QSC_EXPORT_API void qsc_intutils_be8increment(uint8_t* output, size_t outlen);

#if defined(QSC_SYSTEM_HAS_AVX)
/**
* \brief Byte reverse an array of 32-bit integers
*
* \param destination: the destination array
* \param source: [const] the source array
* \param length: the length of the integer array
*/
QSC_EXPORT_API void qsc_intutils_bswap32(uint32_t* destination, const uint32_t* source, size_t length);

/**
* \brief Byte reverse an array of 64-bit integers
*
* \param destination: the destination array
* \param source: [const] the source array
* \param length: the length of the integer array
*/
QSC_EXPORT_API void qsc_intutils_bswap64(uint64_t* destination, const uint64_t* source, size_t length);
#endif

/**
* \brief Set an an 8-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: The number of 8-bit integers to zeroize
*/
QSC_EXPORT_API void qsc_intutils_clear8(uint8_t* a, size_t count);

/**
* \brief Set an an 8-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: The number of 8-bit integers to zeroize
*/
QSC_EXPORT_API void qsc_intutils_clear16(uint16_t* a, size_t count);

/**
* \brief Set an an 32-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: the number of 32-bit integers to zeroize
*/
QSC_EXPORT_API void qsc_intutils_clear32(uint32_t* a, size_t count);

/**
* \brief Set an an 64-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: The number of 64-bit integers to zeroize
*/
QSC_EXPORT_API void qsc_intutils_clear64(uint64_t* a, size_t count);

/**
* \brief Constant-time conditional move function
* b=1 means move, b=0 means don't move
*
* \param dest: The return array
* \param source: [const] The source array
* \param length: The number of bytes to move
* \param cond: The condition
*/
QSC_EXPORT_API void qsc_intutils_cmov(uint8_t* dest, const uint8_t* source, size_t length, uint8_t cond);

/**
* \brief Expand an integer mask in constant time
*
* \param x: The N bit word
* \return: A N bit expanded word
*/
QSC_EXPORT_API size_t qsc_intutils_expand_mask(size_t x);

/**
* \brief Check if an integer is greater or equal to a second integer
*
* \param x: The base integer
* \param y: The comparison integer
* \return: Returns true if the base integer is greater or equal to the comparison integer
*/
QSC_EXPORT_API bool qsc_intutils_are_equal(size_t x, size_t y);

/**
* \brief Check if an integer (x) is greater or equal to a second integer (y)
*
* \param x: The base integer
* \param y: The comparison integer
* \return: Returns true if the base integer is greater or equal to the comparison integer
*/
QSC_EXPORT_API bool qsc_intutils_is_gte(size_t x, size_t y);

/**
* \brief Convert a hex string to an array
*
* \param hexstr: [const] The hexadecimal string
* \param output: The array output
* \param length: The length of the output array
*/
QSC_EXPORT_API void qsc_intutils_hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

/**
* \brief Convert an array to a hex string
*
* \param input: [const] The array input
* \param hexstr: The hexadecimal string output; must be 2x the size of input array
* \param length: The length of the input array
*/
QSC_EXPORT_API void qsc_intutils_bin_to_hex(const uint8_t* input, char* hexstr, size_t length);

/**
* \brief Increment an 8-bit integer array as a segmented little-endian integer
*
* \param output: The source integer 8-bit array
* \param outlen: The length of the output counter array
*/
QSC_EXPORT_API void qsc_intutils_le8increment(uint8_t* output, size_t outlen);

#if defined(QSC_SYSTEM_HAS_AVX)
/**
* \brief Increment the low 64-bit integer of a little endian array by one
*
* \param counter: The counter vector
*/
QSC_EXPORT_API void qsc_intutils_leincrement_x128(__m128i* counter);
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
/**
* \brief Offset increment the low 64-bit integer of a set of 64-bit pairs of a little endian integers (ex. lo + 1,2,3,4)
*
* \param counter: The counter vector
*/
QSC_EXPORT_API void qsc_intutils_leincrement_x512(__m512i* counter);
#endif

/**
* \brief Convert an 8-bit integer array to a 16-bit little-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 16-bit little endian integer
*/
QSC_EXPORT_API uint16_t qsc_intutils_le8to16(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 32-bit little-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 32-bit little endian integer
*/
QSC_EXPORT_API uint32_t qsc_intutils_le8to32(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 64-bit little-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 64-bit little endian integer
*/
QSC_EXPORT_API uint64_t qsc_intutils_le8to64(const uint8_t* input);

/**
* \brief Convert a 16-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 16-bit integer
*/
QSC_EXPORT_API void qsc_intutils_le16to8(uint8_t* output, uint16_t value);

/**
* \brief Convert a 32-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 32-bit integer
*/
QSC_EXPORT_API void qsc_intutils_le32to8(uint8_t* output, uint32_t value);

/**
* \brief Convert a 64-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 64-bit integer
*/
QSC_EXPORT_API void qsc_intutils_le64to8(uint8_t* output, uint64_t value);

/**
* \brief Return the larger of two integers
*
* \param a: The first 32-bit integer
* \param b: The second 32-bit integer
* \return Returns the larger integer
*/
QSC_EXPORT_API size_t qsc_intutils_max(size_t a, size_t b);

/**
* \brief Return the smaller of two integers
*
* \param a: The first 32-bit integer
* \param b: The second 32-bit integer
* \return Returns the smaller integer
*/
QSC_EXPORT_API size_t qsc_intutils_min(size_t a, size_t b);

#if defined(QSC_SYSTEM_HAS_AVX)
/**
* \brief Reverse a 128-bit array
*
* \param input: [const] The first 128-bit integer array
* \param output: The second 128-bit integer
*/
QSC_EXPORT_API void qsc_intutils_reverse_bytes_x128(const __m128i* input, __m128i* output);
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
/**
* \brief Reverse a 512-bit array
*
* \param input: [const] The first 512-bit integer array
* \param output: The second 512-bit integer
*/
QSC_EXPORT_API void qsc_intutils_reverse_bytes_x512(const __m512i* input, __m512i* output);
#endif

/**
* \brief Rotate an unsigned 32-bit integer to the left
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
QSC_EXPORT_API uint32_t qsc_intutils_rotl32(uint32_t value, size_t shift);

/**
* \brief Rotate an unsigned 64-bit integer to the left
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
QSC_EXPORT_API uint64_t qsc_intutils_rotl64(uint64_t value, size_t shift);

/**
* \brief Rotate an unsigned 32-bit integer to the right
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
QSC_EXPORT_API uint32_t qsc_intutils_rotr32(uint32_t value, size_t shift);

/**
* \brief Rotate an unsigned 64-bit integer to the right
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
QSC_EXPORT_API uint64_t qsc_intutils_rotr64(uint64_t value, size_t shift);

/**
* \brief Constant time comparison of two arrays of unsigned 8-bit integers
*
* \param a: [const] The first 8-bit integer array
* \param b: [const] The second 8-bit integer array
* \param length: The number of bytes to check
* \return Returns zero if the arrays are equivalent
*/
QSC_EXPORT_API int32_t qsc_intutils_verify(const uint8_t* a, const uint8_t* b, size_t length);

#endif
