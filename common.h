#ifndef QSC_COMMON_H
#define QSC_COMMON_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Quantum Secure Cryptographic library in C (QSC) */

/* compiler types; not all will be supported (targets are msvc, mingw, gcc, intel, and clang) */
#if defined(_MSC_VER)
#	define QSC_COMPILER_MSC
#elif defined(__MINGW32__)
#	define QSC_COMPILER_MINGW
#elif defined(__CC_ARM)
#	define QSC_COMPILER_ARM
#elif defined(__BORLANDC__)
#	define QSC_COMPILER_BORLAND
#elif defined(__clang__)
#	define QSC_COMPILER_CLANG
#elif defined(__GNUC__)
#	define QSC_COMPILER_GCC
#elif defined(__IBMC__) || defined(__IBMCPP__)
#	define QSC_COMPILER_IBM
#elif defined(__INTEL_COMPILER) || defined(__ICL)
#	define QSC_COMPILER_INTEL
#elif defined(__MWERKS__)
#	define QSC_COMPILER_MWERKS
#elif defined(__OPEN64__)
#	define QSC_COMPILER_OPEN64
#elif defined(__SUNPRO_C)
#	define QSC_COMPILER_SUNPRO
#elif defined(__TURBOC__)
#	define QSC_COMPILER_TURBO
#endif

/* preprocessor os selection (not all OS's will be supported; targets are win/android/linux/ios) */
#if defined(_WIN64) || defined(_WIN32)
#	if !defined(QSC_OS_WINDOWS)
#	define QSC_OS_WINDOWS
#	endif
#	if defined(_WIN64)
#		define QSC_ISWIN64
#	elif defined(_WIN32)
#		define QSC_ISWIN32
#	endif
#elif defined(__ANDROID__)
#	define QSC_OS_ANDROID
#elif defined(__APPLE__) || defined(__MACH__)
#	include "TargetConditionals.h"
#	define QSC_OS_APPLE
#	if defined(TARGET_OS_IPHONE) && defined(TARGET_IPHONE_SIMULATOR)
#		define QSC_ISIPHONESIM
#	elif TARGET_OS_IPHONE
#		define QSC_ISIPHONE
#	else
#		define QSC_ISOSX
#	endif
#elif defined(__linux)
#	define QSC_OS_LINUX
#elif defined(__unix)
#	define QSC_OS_UNIX
#	if defined(__hpux) || defined(hpux)
#		define QSC_OS_HPUX
#	endif
#	if defined(__sun__) || defined(__sun) || defined(sun)
#		define QSC_OS_SUNUX
#	endif
#endif

/* cpu type (only intel/amd/arm are targeted for support) */
#if defined(QSC_COMPILER_MSC)
#	if defined(_M_X64) || defined(_M_AMD64)
#		define QSC_ARCH_X64
#		define QSC_ARCH_X86_X64
#		if defined(_M_AMD64)
#			define QSC_ARCH_AMD64
#		endif
#	elif defined(_M_IX86) || defined(_X86_)
#		define QSC_ARCH_IX86
#		define QSC_ARCH_X86_X64
#	elif defined(_M_ARM)
#		define QSC_ARCH_ARM
#		if defined(_M_ARM_ARMV7VE)
#			define QSC_ARCH_ARMV7VE
#		elif defined(_M_ARM_FP)
#			define QSC_ARCH_ARMFP
#		elif defined(_M_ARM64)
#			define QSC_ARCH_ARM64
#		endif
#	elif defined(_M_IA64)
#		define QSC_ARCH_IA64
#	endif
#elif defined(QSC_COMPILER_GCC)
#	if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64)
#		define QSC_ARCH_X64
#		define QSC_ARCH_X86_X64
#		if defined(_M_AMD64)
#			define QSC_ARCH_AMD64
#		endif
#	elif defined(i386) || defined(__i386) || defined(__i386__)
#		define QSC_ARCH_IX86
#		define QSC_ARCH_X86_X64
#	elif defined(__arm__)
#		define QSC_ARCH_ARM
#		if defined(__aarch64__)
#			define QSC_ARCH_ARM64
#		endif
#	elif defined(__ia64) || defined(__ia64__) || defined(__itanium__)
#		define QSC_ARCH_IA64
#	elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) || defined(__64BIT__) || defined(_LP64) || defined(__LP64__)
#		define QSC_ARCH_PPC
#	elif defined(__sparc) || defined(__sparc__)
#		define QSC_ARCH_SPARC
#		if defined(__sparc64__)
#			define QSC_ARCH_SPARC64
#		endif
#	endif
#endif

#if defined(QSC_ARCH_X64) || defined(QSC_ARCH_ARM64) || defined(QSC_ARCH_IA64) || defined(QSC_ARCH_AMD64) || defined(QSC_ARCH_ARM64) || defined(QSC_ARCH_SPARC64)
#	define QSC_IS_X64
#else
#	define QSC_IS_X86
#endif

/* detect endianess */
#define QSC_IS_LITTLE_ENDIAN (((union { unsigned x; unsigned char c; }){1}).c)

/* define endianess of CPU */
#if (!defined(QSC_IS_LITTLE_ENDIAN))
#	if defined(__sparc) || defined(__sparc__) || defined(__hppa__) || defined(__PPC__) || defined(__mips__) || defined(__MWERKS__) && (!defined(__INTEL__))
#		define QSC_IS_BIG_ENDIAN
#	else
#		define QSC_IS_LITTLE_ENDIAN
#	endif
#endif

#if !defined(__GNUC__)
#	if defined(__attribute__)
#		undef __attribute__
#	endif
#	define __attribute__(a)
#endif

#include <stdbool.h>

#if defined(QSC_OS_WINDOWS)
#	include <stdint.h>
#else
#	include "inttypes.h"
#endif

// Note: AVX512 is currently untested, this flag enables support on a compliant system
//#define QSC_AVX512_SUPPORTED

#if defined(__AVX512F__) && (__AVX512F__ == 1) && defined(QSC_AVX512_SUPPORTED)
#	include <immintrin.h>
#	if (!defined(__AVX512__))
#		define __AVX512__
#	endif
#endif

/* Modifiable values that determine which parameter sets get compiled */

/*!
\def QSC_MCELIECE_SECURITY_LEVEL
* Sets the McEliece security parameter set used by the cipher
* Security level 1: High security, N=6960 T=119
* Security level 2: Highest security, N=8192 T=128
*/
#ifndef QSC_MCELIECE_SECURITY_LEVEL
#	define QSC_MCELIECE_SECURITY_LEVEL 2
#endif

/* Do not modify values beyond this point */

/*!
\def QSC_STATUS_SUCCESS
* Function return value indicates successful operation
*/
static const int32_t QSC_STATUS_SUCCESS = 0;

/*!
\def QSC_STATUS_FAILURE
* Function return value indicates failed operation
*/
static const int32_t QSC_STATUS_FAILURE = -1;

/*!
\def QSC_ERROR_AUTHENTICATION
* Function return value indicates internal failure
*/
static const int32_t QSC_ERROR_INTERNAL = -2;

/*!
\def QSC_ERROR_AUTHENTICATION
* Function return value indicates authntication failure
*/
static const int32_t QSC_ERROR_AUTHENTICATION = -3;

/*!
\def QSC_ERROR_PROVIDER
* Function return value indicates a random provider failure
*/
static const int32_t QSC_ERROR_PROVIDER = -4;

/** internal */

#if (QSC_MCELIECE_SECURITY_LEVEL == 1)
#	define QSC_MCELIECE_CIPHERTEXT_BYTESIZE 0
#	define QSC_MCELIECE_PRIVATEKEY_BYTESIZE 0
#	define QSC_MCELIECE_PUBLICKEY_BYTESIZE 0
#elif (QSC_MCELIECE_SECURITY_LEVEL == 2)
#	define QSC_MCELIECE_CIPHERTEXT_BYTESIZE 0
#	define QSC_MCELIECE_PRIVATEKEY_BYTESIZE 0
#	define QSC_MCELIECE_PUBLICKEY_BYTESIZE 0
#else
#	error The McEliece security level is not supported!
#endif

#endif
