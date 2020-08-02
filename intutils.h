/*
* \file intutils.h
* \brief <b>Integer utilities</b> \n
* This file contains common integer functions
* August 7, 2019
*/

#ifndef QSC_INTUTILS_H
#define QSC_INTUTILS_H

#include "common.h"

/**
* \brief Compare two byte 8-bit integer for equality
*
* \param a: the first array to compare
* \param b: the second array to compare
* \param length: the number of bytes to compare
* \return Returns zero (QSC_STATUS_SUCCESS) for equal values
*/
bool are_equal8(const uint8_t* a, const uint8_t* b, size_t length);

/**
* \brief Convert an 8-bit integer array to a 16-bit big-endian integer
*
* \param input: the source integer 8-bit array
* \return the 16-bit big endian integer
*/
uint16_t be8to16(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 32-bit big-endian integer
*
* \param input: the source integer 8-bit array
* \return the 32-bit big endian integer
*/
uint32_t be8to32(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 64-bit big-endian integer
*
* \param input: the source integer 8-bit array
* \return the 64-bit big endian integer
*/
uint64_t be8to64(const uint8_t* input);

/**
* \brief Convert a 16-bit integer to a big-endian 8-bit integer array
*
* \param output: the 8-bit integer array
* \param value: the 16-bit integer
*/
void be16to8(uint8_t* output, uint16_t value);

/**
* \brief Convert a 32-bit integer to a big-endian 8-bit integer array
*
* \param output: the 8-bit integer array
* \param value: the 32-bit integer
*/
void be32to8(uint8_t* output, uint32_t value);

/**
* \brief Convert a 64-bit integer to a big-endian 8-bit integer array
*
* \param output: the 8-bit integer array
* \param value: the 64-bit integer
*/
void be64to8(uint8_t* output, uint64_t value);

/**
* \brief Increment an 8-bit integer array as a segmented big-endian integer
*
* \param output: the source integer 8-bit array
* \param outlen: the length of the output counter array
*/
void be8increment(uint8_t* output, size_t outlen);

/**
* \brief Set an an 8-bit integer array to zeroes
*
* \param a: the array to clear
* \param count: the number of integers to clear
*/
void clear8(uint8_t* a, size_t count);

/**
* \brief Set an an 32-bit integer array to zeroes
*
* \param a: the array to clear
* \param count: the number of integers to clear
*/
void clear32(uint32_t* a, size_t count);

/**
* \brief Set an an 64-bit integer array to zeroes
*
* \param a: the array to clear
* \param count: the number of integers to clear
*/
void clear64(uint64_t* a, size_t count);

/* b = 1 means mov, b = 0 means don't mov*/
/**
* \brief Conditional move function
*
* \param r The return array
* \param x The source array
* \param len The number of bytes to move
* \param The condition
*/
void cmov(uint8_t* r, const uint8_t* x, size_t len, uint8_t b);

/**
* \brief Increment an 8-bit integer array as a segmented little-endian integer
*
* \param output: the source integer 8-bit array
* \param outlen: the length of the output counter array
*/
void le8increment(uint8_t* output, size_t outlen);

/**
* \brief Convert an 8-bit integer array to a 16-bit little-endian integer
*
* \param input: the source integer 8-bit array
* \return the 16-bit little endian integer
*/
uint16_t le8to16(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 32-bit little-endian integer
*
* \param input: the source integer 8-bit array
* \return the 32-bit little endian integer
*/
uint32_t le8to32(const uint8_t* input);

/**
* \brief Convert an 8-bit integer array to a 64-bit little-endian integer
*
* \param input: the source integer 8-bit array
* \return the 64-bit little endian integer
*/
uint64_t le8to64(const uint8_t* input);

/**
* \brief Convert a 16-bit integer to a little-endian 8-bit integer array
*
* \param output: the 8-bit integer array
* \param value: the 16-bit integer
*/
void le16to8(uint8_t* output, uint16_t value);

/**
* \brief Convert a 32-bit integer to a little-endian 8-bit integer array
*
* \param output: the 8-bit integer array
* \param value: the 32-bit integer
*/
void le32to8(uint8_t* output, uint32_t value);

/**
* \brief Convert a 64-bit integer to a little-endian 8-bit integer array
*
* \param output: the 8-bit integer array
* \param value: the 64-bit integer
*/
void le64to8(uint8_t* output, uint64_t value);

/**
* \brief Return the larger of two integers
*
* \param a: the first 32-bit integer
* \param b: the second 32-bit integer
* \return the larger integer
*/
size_t maxu(size_t a, size_t b);

/**
* \brief Return the smaller of two integers
*
* \param a: the first 32-bit integer
* \param b: the second 32-bit integer
* \return the smaller integer
*/
size_t minu(size_t a, size_t b);

/**
* \brief Rotate an unsigned 32-bit integer to the left
*
* \param value: the value to rotate
* \param shift: the bit shift register
* \return the rotated integer
*/
uint32_t rotl32(uint32_t value, size_t shift);

/**
* \brief Rotate an unsigned 64-bit integer to the left
*
* \param value: the value to rotate
* \param shift: the bit shift register
* \return the rotated integer
*/
uint64_t rotl64(uint64_t value, size_t shift);

/**
* \brief Rotate an unsigned 32-bit integer to the right
*
* \param value: the value to rotate
* \param shift: the bit shift register
* \return the rotated integer
*/
uint32_t rotr32(uint32_t value, size_t shift);

/**
* \brief Rotate an unsigned 64-bit integer to the right
*
* \param value: the value to rotate
* \param shift: the bit shift register
* \return the rotated integer
*/
uint64_t rotr64(uint64_t value, size_t shift);

/**
* \brief Constant time comparison of two 8-bit arrays
*
* \param a: the first 8-bit integer array
* \param b: the second 8-bit integer array
* \return zero if the arrays are equivalent
*/
int32_t verify(const uint8_t* a, const uint8_t* b, size_t length);

#endif
