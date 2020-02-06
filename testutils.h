#ifndef QSCTEST_TEST_UTILS_H
#define QSCTEST_TEST_UTILS_H

#include "common.h"

/**
* \brief Convert a hexadecimal character string to a binary byte array
*
* \param hexstr: the string to convert
* \param output: the binary output array
* \param length: the number of bytes to convert
*/
void hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

/**
* \brief Convert a binary array to a hexidecimal string and print to the console
*
* \param input: the binary array
* \param inputlen: the number of bytes to process
* \param linelen: the length of output to print, before starting a new line
*/
void print_hex(const uint8_t* input, size_t inputlen, size_t linelen);

#endif
