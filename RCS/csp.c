#include "csp.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <tchar.h>
#	include <windows.h>
#	include <Wincrypt.h>
#	pragma comment(lib, "crypt32.lib")

#else
#	include <sys/types.h> /* TODO: are all of these really needed? */
#	include <sys/stat.h>
#	include <errno.h>
#	include <fcntl.h>
#	include <stdlib.h>
#	include <stdio.h>
#	include <unistd.h>
#	ifndef O_NOCTTY
#		define O_NOCTTY 0
#	endif
#	define CEX_SYSTEM_RNG_DEVICE "/dev/urandom"
#endif

bool qsc_csp_generate(uint8_t* output, size_t length)
{
	assert(output != 0);
	assert(length <= QSC_CSP_SEED_MAX);

	bool res;

	res = true;

#if defined(QSC_SYSTEM_OS_WINDOWS)

	HCRYPTPROV hprov;

	if (CryptAcquireContextW(&hprov, 0, 0, PROV_RSA_FULL, (CRYPT_VERIFYCONTEXT | CRYPT_SILENT)))
	{
		if (!CryptGenRandom(hprov, (DWORD)length, output))
		{
			res = false;
		}
	}
	else
	{
		res = false;
	}

	if (hprov)
	{
		CryptReleaseContext(hprov, 0);
	}

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