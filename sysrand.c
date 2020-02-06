#include "sysrand.h"

#ifndef WIN32
#	if defined(_WIN64) || defined(_WIN32)
#		define WIN32
#	endif
#endif

#ifdef WIN32
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

int32_t sysrand_getbytes(uint8_t* buffer, size_t length)
{
	int32_t status;

	status = 0;

#ifdef WIN32

	HCRYPTPROV hprov;

	if (CryptAcquireContextW(&hprov, 0, 0, PROV_RSA_FULL, (CRYPT_VERIFYCONTEXT | CRYPT_SILENT)))
	{
		if (!CryptGenRandom(hprov, (DWORD)length, buffer))
		{
			status = -1;
		}
	}
	else
	{
		status = -1;
	}

	if (hprov)
	{
		CryptReleaseContext(hprov, 0);
	}

#else

	int32_t fd = open("/dev/urandom", O_RDONLY);

	if (fd <= 0)
	{
		status = -1;
	}
	else
	{
		int32_t r = read(fd, buffer, length);

		if (r != length)
		{
			status = -1;
		}

		close(fd);
	}

#endif

	return status;
}