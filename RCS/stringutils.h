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

#ifndef QSC_STRINGUTILS_H
#define QSC_STRINGUTILS_H

#include "common.h"

/*
* \file stringutils.h
* \brief String utilities; common string support functions
*/

/*!
* \def QSC_STRINGUTILS_TOKEN_NOT_FOUND
* \brief The search token was not found
*/
#define QSC_STRINGUTILS_TOKEN_NOT_FOUND -1

/**
* \brief Counts all white-spaces, line stops, and returns from a string
*
* \param dest: [const] The string dest to check
* \param dstlen: The size of the dest string
* \return Returns the number of line stops, carriage returns and white-spaces in the string
*/
QSC_EXPORT_API size_t qsc_stringutils_formatting_count(const char* dest, size_t dstlen);

/**
* \brief Remove all white-spaces, lines stops, and returns from a string
*
* \param source: [const] The source string to copy from
* \param srclen: The size of the source string
* \param dest: The string receiving the filtered characters
* \return Returns the number of characters copied
*/
QSC_EXPORT_API size_t qsc_stringutils_formatting_filter(const char* source, size_t srclen, char* dest);

/**
* \brief Add line breaks to a string at a line length interval
*
* \param dest: The string receiving the formatted text
* \param dstlen: The size of the dest array
* \param linelen: The line length where a new line character is placed
* \param source: [const] The source string to copy from
* \param srclen: The length of the source array
* \return Returns the size of the dest string
*/
QSC_EXPORT_API size_t qsc_stringutils_add_line_breaks(char* dest, size_t dstlen, size_t linelen, const char* source, size_t srclen);

/**
* \brief Removes all line breaks from a string
*
* \param dest: The string receiving the formatted text
* \param dstlen: The size of the dest array
* \param source: [const] The source string to copy from
* \param srclen: The length of the source array
* \return Returns the size of the dest string
*/
QSC_EXPORT_API size_t qsc_stringutils_remove_line_breaks(char* dest, size_t dstlen, const char* source, size_t srclen);

/**
* \brief Clear a string of data
*
* \param source: The string to clear
*/
QSC_EXPORT_API void qsc_stringutils_clear_string(char* source);

/**
* \brief Clear a length of data from a string
*
* \param dest: The string dest to clear
* \param length: The number of characters to clear
*/
QSC_EXPORT_API void qsc_stringutils_clear_substring(char* dest, size_t length);

/**
* \brief Compare two strings for equivalence
*
* \param str1: [const] The first string
* \param str2: [const] The second string
* \param length: The number of characters to compare
* \return Returns true if the strings are equal
*/
QSC_EXPORT_API bool qsc_stringutils_compare_strings(const char* str1, const char* str2, size_t length);

/**
* \brief Concatenate two strings
*
* \param dest: The destination dest
* \param dstlen: The size of the destination dest
* \param source: [const] The source string to copy
* \return Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_concat_strings(char* dest, size_t dstlen, const char* source);

/**
* \brief Concatenate two strings and copy them to a third string
*
* \param dest: The destination string to copy to
* \param dstlen: The size of the destination dest
* \param str1: [const] The first string to copy from
* \param str2: [const] The second string to copy from
* \return Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_concat_and_copy(char* dest, size_t dstlen, const char* str1, const char* str2);

/**
* \brief Copy a length of one string to another
*
* \param dest: The destination string to copy to
* \param dstlen: The size of the destination dest
* \param source: [const] The string to copy from
* \param srclen: The substring length
* \return Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_copy_substring(char* dest, size_t dstlen, const char* source, size_t srclen);

/**
* \brief Copy a source string to a destination string
*
* \param dest: The destination string to copy to
* \param dstlen: The size of the destination dest
* \param source: [const] The string to copy from
* \return Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_copy_string(char* dest, size_t dstlen, const char* source);

/**
* \brief Find a substrings position within a string
*
* \param source: [const] The string to check for the substring
* \param token: [const] The substring to search for
* \return Returns the character position within the string, or QSC_STRINGUTILS_TOKEN_NOT_FOUND if the string is not found
*/
QSC_EXPORT_API int32_t qsc_stringutils_find_string(const char* source, const char* token);

/**
* \brief Inserts a substring into a string
*
* \param dest: The string receiving the substring
* \param dstlen: The size of the source dest
* \param source: [const] The substring to insert
* \param offset: The insertion starting position within the source string; position is ordinal, 0-n
* \return Returns the size of the new string, or QSC_STRINGUTILS_TOKEN_NOT_FOUND if the string insert operation failed
*/
QSC_EXPORT_API int32_t qsc_stringutils_insert_string(char* dest, size_t dstlen, const char* source, size_t offset);

/**
* \brief Check that a string contains only alpha numeric ASCII characters
*
* \param source: [const] The string to check for alpha numeric characters
* \param srclen: The number of characters to check
* \return Returns true if the string is alpha numeric
*/
QSC_EXPORT_API bool qsc_stringutils_is_alpha_numeric(const char* source, size_t srclen);

/**
* \brief Check that a string contains only hexadecimal ASCII characters
*
* \param source: [const] The string to check for hexadecimal characters
* \param srclen: The number of characters to check
* \return Returns true if the string is hexadecimal
*/
QSC_EXPORT_API bool qsc_stringutils_is_hex(const char* source, size_t srclen);

/**
* \brief Check that a string contains only numeric ASCII characters
*
* \param source: [const] The string to check for numeric characters
* \param srclen: The number of characters to check
* \return Returns true if the string is numeric
*/
QSC_EXPORT_API bool qsc_stringutils_is_numeric(const char* source, size_t srclen);

/**
* \brief Join an array of strings to form one string
*
* \warning The string returned must be deleted by the caller
*
* \param source: The array of substrings
* \param count: The number of substring arrays
* \return Returns a concatenated string
*/
QSC_EXPORT_API char* qsc_stringutils_join_string(char** source, size_t count);

/**
* \brief Find a substring within a string, searching in reverse
*
* \param source: [const] The string to check for the substring
* \param token: [const] The token separator
* \return Returns the substring, or NULL if not found
*/
QSC_EXPORT_API const char* qsc_stringutils_reverse_sub_string(const char* source, const char* token);

/**
* \brief Test if the string contains a substring
*
* \param source: [const] The string to check for the substring
* \param token: [const] The substring to search for
* \return Returns true if the substring is found
*/
QSC_EXPORT_API bool qsc_stringutils_string_contains(const char* source, const char* token);

/**
* \brief Split a string into a substring 2-dimensional array
*
* \warning The array of strings returned must be freed by the caller
*
* \param source: The string to split
* \param delim: [const] The char delimiter used to split the string
* \param count: The number of substrings in the new array
* \return Returns a 2 dimensional character array of substrings
*/
QSC_EXPORT_API char** qsc_stringutils_split_string(char* source, const char* delim, size_t* count);

/**
* \brief Split a string into two substrings
*
* \param dest1: The first destination string
* \param dest2: The second destination string
* \param destlen: The destination strings length
* \param [const] source: The source string
* \param [const] token: The search token
*/
QSC_EXPORT_API void qsc_stringutils_split_strings(char* dest1, char* dest2, size_t destlen, const char* source, const char* token);

/**
* \brief Find a substring within a string
*
* \warning The string returned must be deleted by the caller
*
* \param source: [const] The string to check for the substring
* \param token: [const] The token separator
* \return Returns the substring, or NULL if not found
*/
QSC_EXPORT_API char* qsc_stringutils_sub_string(const char* source, const char* token);

/**
* \brief Convert a string to a 32-bit integer
*
* \param source: [const] The string to convert to an integer
* \return Returns the converted integer
*/
QSC_EXPORT_API int32_t qsc_stringutils_string_to_int(const char* source);

/**
* \brief Get the character length of a string
*
* \param source: [const] The source string pointer
* \return Returns the size of the string
*/
QSC_EXPORT_API size_t qsc_stringutils_string_size(const char* source);

/**
* \brief Convert a 32-bit signed integer to a string
*
* \param num: The integer to convert
* \param dest: The destination string
* \param dstlen: The size of the output dest
*/
QSC_EXPORT_API void qsc_stringutils_int_to_string(int32_t num, char* dest, size_t dstlen);

/**
* \brief Convert a string to all lower-case characters
*
* \param source: The string to convert to lower-case
*/
QSC_EXPORT_API void qsc_stringutils_to_lowercase(char* source);

/**
* \brief Convert a string to all upper-case characters
*
* \param source: The string to convert to upper-case
*/
QSC_EXPORT_API void qsc_stringutils_to_uppercase(char* source);

/**
* \brief Trim null and newline characters from a string
*
* \param source: The string to trim
*/
QSC_EXPORT_API void qsc_stringutils_trim_newline(char* source);

/**
* \brief Count all the white-spaces in a string
*
* \param source: [const] The string dest to check
* \param srclen: The size of the dest string
* \return Returns the number of white-spaces in the string
*/
QSC_EXPORT_API size_t qsc_stringutils_whitespace_count(const char* source, size_t srclen);

/**
* \brief Remove all the white-spaces from a string
*
* \param source: [const] The source string to copy from
* \param srclen: The size of the source string
* \param dest: The destination string receiving the filtered characters
* \return Returns the number of characters copied
*/
QSC_EXPORT_API size_t qsc_stringutils_whitespace_filter(const char* source, size_t srclen, char* dest);

#endif
