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

#ifndef QSC_CONSOLEUTILS_H
#define QSC_CONSOLEUTILS_H

/*
* \file consoleutils.h
* \brief Console support functions
*/

#include "common.h"

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

#if !defined(wint_t)
    #define wint_t char
#endif

/*!
\def QSC_CONSOLE_MAX_LINE
* The maximum length of a console string
*/
#define QSC_CONSOLE_MAX_LINE 128

/*! \enum qsc_console_font_color
* \brief The console color choices
*/
typedef enum qsc_console_font_color
{
	white = 0,		/*!< White */
	blue = 1,		/*!< Blue */
	green = 2,		/*!< Green */
	red = 3			/*!< Red */
} qsc_console_font_color;

/*! \enum qsc_console_font_style
* \brief The console font style
*/
typedef enum qsc_console_font_style
{
	regular = 0,	/*!< Regular */
	bold = 1,		/*!< Bold */
	italic = 2,		/*!< Italic */
	bolditalic = 3	/*!< Bold and Italic */
} qsc_console_font_style;

/**
* \brief Color a line of console text
*
* \param message: [const] The message string
* \param color: The color of the text
*/
QSC_EXPORT_API void qsc_consoleutils_colored_message(const char* message, qsc_console_font_color color);

/**
* \brief A blocking wait that returns a single character from console input
*
* \return Returns the character detected
*/
QSC_EXPORT_API char qsc_consoleutils_get_char(void);

/**
* \brief Get a string of characters from the console
*
* \param line: The string of text received
* \param maxlen: The maximum text length
*
* \return Returns the number of characters in the line
*/
QSC_EXPORT_API size_t qsc_consoleutils_get_line(char* line, size_t maxlen);

/**
* \brief Get a string of characters from the console that is lowercase and trimmed
*
* \param line: The string of text received
* \param maxlen: The maximum text length
* \return Returns the number of characters in the line
*/
QSC_EXPORT_API size_t qsc_consoleutils_get_formatted_line(char* line, size_t maxlen);

/**
* \brief Pause the console until user input is detected
*
* \return Returns the number of character
*/
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
QSC_EXPORT_API wint_t qsc_consoleutils_get_wait(void);
#else
QSC_EXPORT_API char qsc_consoleutils_get_wait(void);
#endif

/**
* \brief Convert a hexadecimal character string to a character byte array
*
* \param hexstr: [const] The string to convert
* \param output: The character output array
* \param length: The number of characters to convert
*/
QSC_EXPORT_API void qsc_consoleutils_hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

/**
* \brief Find a set of characters in a line of console text.
*
* \param line: [const] The string of text received
* \param token: [const] The string to search for
*/
QSC_EXPORT_API bool qsc_consoleutils_line_contains(const char* line, const char* token);

/**
* \brief Gets a password masked on the console screen
*
* \param output: The output character array
* \param outlen: The maximum size of the output array
* \return Returns the size of the password
*/
QSC_EXPORT_API size_t qsc_consoleutils_masked_password(char* output, size_t outlen);

/**
* \brief User confirmation that and action can continue(Y/N y/n)
*
* \param message: [const] The message to print
* \return Returns the size of the password
*/
QSC_EXPORT_API bool qsc_consoleutils_message_confirm(const char* message);

/**
* \brief Print a byte array
*
* \param input: [const] The character array
* \param inputlen: The number of characters to print
* \param linelen: The length of output to print, before starting a new line
*/
QSC_EXPORT_API void qsc_consoleutils_print_array(const uint8_t* input, size_t inputlen, size_t linelen);

/**
* \brief Convert a character array to a hexadecimal string and print to the console
*
* \param input: [const] The character array
* \param inputlen: The number of characters to print
* \param linelen: The length of output to print, before starting a new line
*/
QSC_EXPORT_API void qsc_consoleutils_print_hex(const uint8_t* input, size_t inputlen, size_t linelen);

/**
* \brief Print a string to the console, ignoring special characters
*
* \param input: [const] The character array
* \param inputlen: The number of characters to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_formatted(const char* input, size_t inputlen);

/**
* \brief Print a string to the console, ignoring special characters, and add a line break
*
* \param input: [const] The character array
* \param inputlen: The number of characters to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_formatted_line(const char* input, size_t inputlen);

/**
* \brief Print an array of characters to the console
*
* \param input: [const] The character array to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_safe(const char* input);

/**
* \brief Print an array of characters to the console with a line break
*
* \param input: [const] The character array to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_line(const char* input);

/**
* \brief Print a concatenated set of character arrays, to the console with a line break between each.
*
* \param input: [const] The two dimensional character array to print
* \param count: The number of arrays contained in input
*/
QSC_EXPORT_API void qsc_consoleutils_print_concatenated_line(const char** input, size_t count);

/**
* \brief Print an unsigned 32-bit integer
*
* \param digit: The number to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_uint(uint32_t digit);

/**
* \brief Print an unsigned 64-bit integer
*
* \param digit: The number to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_ulong(uint64_t digit);

/**
* \brief Print a double integer
*
* \param digit: The number to print
*/
QSC_EXPORT_API void qsc_consoleutils_print_double(double digit);

/**
* \brief Prints a small spinning counter
*
* \param seconds: The number of seconds to run
*/
QSC_EXPORT_API void qsc_consoleutils_progress_counter(int32_t seconds);

/**
* \brief Set the size of the window vertical scroll buffer
*
* \param width: The scroll buffer width
* \param height: The scroll buffer height
*/
QSC_EXPORT_API void qsc_consoleutils_set_window_buffer(size_t width, size_t height);

/**
* \brief Clear the text from the window
*/
QSC_EXPORT_API void qsc_consoleutils_set_window_clear(void);

/**
* \brief Set the window prompt string
*
* \param prompt: [const] The prompt string
*/
QSC_EXPORT_API void qsc_consoleutils_set_window_prompt(const char* prompt);

/**
* \brief Set the initial size of the console window
*
* \param width: The window width
* \param height: The window height
*/
QSC_EXPORT_API void qsc_consoleutils_set_window_size(size_t width, size_t height);

/**
* \brief Set the window title string
*
* \param title: [const] The title string
*/
QSC_EXPORT_API void qsc_consoleutils_set_window_title(const char* title);

/**
* \brief Enable virtual terminal mode
*/
QSC_EXPORT_API void qsc_consoleutils_set_virtual_terminal(void);

#endif
