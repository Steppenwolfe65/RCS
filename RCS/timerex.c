#include "timerex.h"
#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#	include "memutils.h"
#endif

void qsc_timerex_get_date(char output[QSC_TIMEREX_TIMESTAMP_MAX])
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	struct tm nt;
	char tbuf[QSC_TIMEREX_TIMESTAMP_MAX] = { 0 };
	__time64_t lt;
	errno_t err;
	size_t len;

	lt = 0;
	memset(output, 0x00, QSC_TIMEREX_TIMESTAMP_MAX);

	_time64(&lt);
	err = localtime_s(&nt, &lt);

	if (err == 0)
	{
		len = strftime(tbuf, QSC_TIMEREX_TIMESTAMP_MAX, "%F", &nt);

		if (len > 0 && len < QSC_TIMEREX_TIMESTAMP_MAX)
		{
			memcpy(output, tbuf, len);
		}
	}
#else
	time_t rt;
	struct tm* ti;
	char buf[QSC_TIMEREX_TIMESTAMP_MAX];
	size_t len;

	memset(output, 0x00, QSC_TIMEREX_TIMESTAMP_MAX);
	time(&rt);

	ti = localtime(&rt);
	strftime(buf, QSC_TIMEREX_TIMESTAMP_MAX, "%F", ti);

	len = strlen(buf);

	if (len > 0 && len < QSC_TIMEREX_TIMESTAMP_MAX)
	{
		memcpy(output, buf, len);
	}
#endif
}

void qsc_timerex_get_datetime(char output[QSC_TIMEREX_TIMESTAMP_MAX])
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	struct tm nt;
	char tbuf[QSC_TIMEREX_TIMESTAMP_MAX] = { 0 };
	__time64_t lt;
	errno_t err;
	size_t len;

	lt = 0;
	memset(output, 0x00, QSC_TIMEREX_TIMESTAMP_MAX);

	_time64(&lt);
	err = _localtime64_s(&nt, &lt);

	if (err == 0)
	{
		err = asctime_s(tbuf, QSC_TIMEREX_TIMESTAMP_MAX, &nt);
		len = strlen(tbuf);

		if (err == 0 && len > 0 && len < QSC_TIMEREX_TIMESTAMP_MAX)
		{
			memcpy(output, tbuf, len);
		}
	}
#else
	time_t rt;
	struct tm* ti;
	char* ct;

	size_t len;

	memset(output, 0x00, QSC_TIMEREX_TIMESTAMP_MAX);
	rt = time(NULL);
	ti = localtime(&rt);
	ct = asctime(ti);

	if (ct != NULL)
	{
		len = strlen(ct);
		memcpy(output, ct, len);
	}
#endif
}

void qsc_timerex_get_time(char output[QSC_TIMEREX_TIMESTAMP_MAX])
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	struct tm nt;
	char tbuf[QSC_TIMEREX_TIMESTAMP_MAX] = { 0 };
	__time64_t lt;
	errno_t err;
	size_t len;

	lt = 0;
	memset(output, 0x00, QSC_TIMEREX_TIMESTAMP_MAX);

	_time64(&lt);
	err = localtime_s(&nt, &lt);

	if (err == 0)
	{
		len = strftime(tbuf, QSC_TIMEREX_TIMESTAMP_MAX, "%T", &nt);

		if (len > 0 && len < QSC_TIMEREX_TIMESTAMP_MAX)
		{
			memcpy(output, tbuf, len);
		}
	}
#else
	time_t rt;
	struct tm* ti;
	char buf[QSC_TIMEREX_TIMESTAMP_MAX];
	size_t len;

	memset(output, 0x00, QSC_TIMEREX_TIMESTAMP_MAX);
	time(&rt);
	ti = localtime(&rt);
	strftime(buf, QSC_TIMEREX_TIMESTAMP_MAX, "%T", ti);

	len = strlen(buf);

	if (len > 0 && len < QSC_TIMEREX_TIMESTAMP_MAX)
	{
		memcpy(output, buf, len);
	}
#endif
}

clock_t qsc_timerex_stopwatch_start()
{
	clock_t start;

	start = clock();

	return start;
}

uint64_t qsc_timerex_stopwatch_elapsed(clock_t start)
{
	clock_t diff;
	uint64_t msec;

	diff = clock() - start;
	msec = (diff * 1000) / CLOCKS_PER_SEC;

	return msec;
}

#if defined(QSC_DEBUG_MODE)
void qsc_timerex_print_values()
{
	char tmro[QSC_TIMEREX_TIMESTAMP_MAX] = { 0 };

	clock_t elps;
	uint64_t tms;

	elps = qsc_timerex_stopwatch_start();

	qsc_consoleutils_print_line("Timer visual verification test");
	qsc_consoleutils_print_line("Printing output from timer functions..");

	qsc_consoleutils_print_safe("Date: ");
	qsc_timerex_get_date(tmro);
	qsc_consoleutils_print_line(tmro);
	qsc_memutils_clear(tmro, sizeof(tmro));

	qsc_consoleutils_print_safe("Date-time: ");
	qsc_timerex_get_datetime(tmro);
	qsc_consoleutils_print_line(tmro);
	qsc_memutils_clear(tmro, sizeof(tmro));

	qsc_consoleutils_print_safe("Time: ");
	qsc_timerex_get_time(tmro);
	qsc_consoleutils_print_line(tmro);
	qsc_memutils_clear(tmro, sizeof(tmro));

	qsc_consoleutils_print_safe("Elapsed: ");
	tms = qsc_timerex_stopwatch_elapsed(elps);
	qsc_consoleutils_print_ulong(tms);
	qsc_consoleutils_print_line("");
}
#endif
