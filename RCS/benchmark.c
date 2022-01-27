#include "benchmark.h"
#include "csp.h"
#include "testutils.h"
#include "timerex.h"
#include "rcs.h"
#include "sha3.h"

/* bs*sc = 1GB */
#define BUFFER_SIZE 1024
#define SAMPLE_COUNT 1000000
#define ONE_GIGABYTE 1024000000

static void rcs256_speed_test()
{
	uint8_t enc[BUFFER_SIZE + QSC_RCS256_MAC_SIZE] = { 0 };
	uint8_t key[QSC_RCS256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0 };
	qsc_rcs_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rcs_keyparams kp = { key, sizeof(key), nonce, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_rcs_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rcs_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("RCS-256 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rcs512_speed_test()
{
	uint8_t enc[BUFFER_SIZE + QSC_RCS512_MAC_SIZE] = { 0 };
	uint8_t key[QSC_RCS512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0 };
	qsc_rcs_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rcs_keyparams kp = { key, sizeof(key), nonce, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_rcs_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rcs_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("RCS-512 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

void qsctest_rcs_speed_run()
{
	qsctest_print_line("Running the RCS-256 performance benchmarks.");
	rcs256_speed_test();

	qsctest_print_line("Running the RCS-512 performance benchmarks.");
	rcs512_speed_test();
}
