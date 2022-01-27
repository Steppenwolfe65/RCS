#include "testutils.h"
#include <stdio.h>

char qsctest_get_char()
{
	char line[8] = { 0 };
	char res;

	res = '0';

	if (fgets(line, sizeof(line), stdin) != NULL)
	{
		res = line[0];
	}

	return res;
}

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
char qsctest_get_wait()
{
	char c;

	c = (wint_t)getwchar();

	return c;
}
#else
char qsctest_get_wait()
{
	char c;

	c = getchar();

	return c;
}
#endif

void qsctest_hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
{
	uint8_t idx0;
	uint8_t idx1;

	const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	memset(output, 0, length);

	for (size_t pos = 0; pos < (length * 2); pos += 2)
	{
		idx0 = ((uint8_t)hexstr[pos + 0] & 0x1FU) ^ 0x10U;
		idx1 = ((uint8_t)hexstr[pos + 1] & 0x1FU) ^ 0x10U;
		output[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	}
}

void qsctest_print_hex(const uint8_t* input, size_t inputlen, size_t linelen)
{
	size_t i;

	while (inputlen >= linelen)
	{
		for (i = 0; i < linelen; ++i)
		{
#if defined(_MSC_VER)
			printf_s("%02X", input[i]);
#else
			printf("%02X", input[i]);
#endif
		}

		input += linelen;
		inputlen -= linelen;
		qsctest_print_safe("\n");
	}

	if (inputlen != 0)
	{
		for (i = 0; i < inputlen; ++i)
		{
#if defined(_MSC_VER)
			printf_s("%02X", input[i]);
#else
			printf("%02X", input[i]);
#endif
		}
	}
}

void qsctest_print_safe(const char* input)
{
	if (input != NULL)
	{
#if defined(_MSC_VER)
		printf_s(input);
#else
		printf("%s", input);
#endif
	}
}

void qsctest_print_line(const char* input)
{
	qsctest_print_safe(input);
	qsctest_print_safe("\n");
}

void qsctest_print_ulong(uint64_t digit)
{
#if defined(_MSC_VER)
	printf_s("%llu", digit);
#else
	printf("%llu", (unsigned long long)digit);
#endif
}

void qsctest_print_double(double digit)
{
#if defined(_MSC_VER)
	printf_s("%.*lf", 3, digit);
#else
	printf("%.*lf", 3, digit);
#endif
}

bool qsctest_test_confirm(const char* message)
{
	char ans;
	bool res;

	qsctest_print_line(message);

	res = false;
	ans = qsctest_get_char();

	if (ans == 'y' || ans == 'Y')
	{
		res = true;
	}

	return res;
}
