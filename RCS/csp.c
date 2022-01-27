#include "csp.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <Windows.h>
#   if defined(QSC_SYSTEM_COMPILER_MSC)
#	    pragma comment(lib, "advapi32.lib")
#   endif
#else
#	include <sys/types.h>
#	include <sys/stat.h>
#	include <errno.h>
#	include <fcntl.h>
#	include <limits.h>
#	include <stdlib.h>
#	include <stdio.h>
#	include <sys/types.h>
#	include <unistd.h>
#	if !defined(O_NOCTTY)
#		define O_NOCTTY 0
#	endif
#endif

#if defined(__OpenBSD__) || defined(__CloudABI__) || defined(__wasi__)
#	define HAVE_SAFE_ARC4RANDOM
#endif

bool qsc_csp_generate(uint8_t* output, size_t length)
{
	assert(output != 0);
	assert(length <= QSC_CSP_SEED_MAX);

	bool res;

	res = true;

#if defined(QSC_SYSTEM_OS_WINDOWS)

	HCRYPTPROV hprov;

	if (CryptAcquireContextW(&hprov, 0, 0, PROV_RSA_FULL, (CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) == true)
	{
		if (CryptGenRandom(hprov, (DWORD)length, output) == false)
		{
			res = false;
		}
	}
	else
	{
		res = false;
	}

	if (hprov != 0)
	{
		CryptReleaseContext(hprov, 0);
	}

#elif defined(HAVE_SAFE_ARC4RANDOM)

	arc4random_buf(output, length);

#else

	int32_t fd = open("/dev/urandom", O_RDONLY);

	if (fd <= 0)
	{
		res = false;
	}
	else
	{
		int32_t r = read(fd, output, length);

		if (r != length)
		{
			res = false;
		}

		close(fd);
	}

#endif

	return res;
}
