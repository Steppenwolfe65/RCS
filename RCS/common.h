/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2020 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>. */

#ifndef QSC_COMMON_H
#define QSC_COMMON_H

#include <assert.h>
#include <intrin.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Quantum Secure Cryptographic library in C (QSC) */

/* compiler types; not all will be supported (targets are msvc, mingw, gcc, intel, and clang) */
#if defined(_MSC_VER)
#	define QSC_SYSTEM_COMPILER_MSC
#elif defined(__MINGW32__)
#	define QSC_SYSTEM_COMPILER_MINGW
#elif defined(__CC_ARM)
#	define QSC_SYSTEM_COMPILER_ARM
#elif defined(__BORLANDC__)
#	define QSC_SYSTEM_COMPILER_BORLAND
#elif defined(__clang__)
#	define QSC_SYSTEM_COMPILER_CLANG
#elif defined(__GNUC__)
#	define QSC_SYSTEM_COMPILER_GCC
#elif defined(__IBMC__) || defined(__IBMCPP__)
#	define QSC_SYSTEM_COMPILER_IBM
#elif defined(__INTEL_COMPILER) || defined(__ICL)
#	define QSC_SYSTEM_COMPILER_INTEL
#elif defined(__MWERKS__)
#	define QSC_SYSTEM_COMPILER_MWERKS
#elif defined(__OPEN64__)
#	define QSC_SYSTEM_COMPILER_OPEN64
#elif defined(__SUNPRO_C)
#	define QSC_SYSTEM_COMPILER_SUNPRO
#elif defined(__TURBOC__)
#	define QSC_SYSTEM_COMPILER_TURBO
#endif

/* preprocessor os selection (not all OS's will be supported; targets are win/android/linux/ios) */
#if defined(_WIN64) || defined(_WIN32)
#	if !defined(QSC_SYSTEM_OS_WINDOWS)
#	define QSC_SYSTEM_OS_WINDOWS
#	endif
#	if defined(_WIN64)
#		define QSC_SYSTEM_ISWIN64
#	elif defined(_WIN32)
#		define QSC_SYSTEM_ISWIN32
#	endif
#elif defined(__ANDROID__)
#	define QSC_SYSTEM_OS_ANDROID
#elif defined(__APPLE__) || defined(__MACH__)
#	include "TargetConditionals.h"
#	define QSC_SYSTEM_OS_APPLE
#	if defined(TARGET_OS_IPHONE) && defined(TARGET_IPHONE_SIMULATOR)
#		define QSC_SYSTEM_ISIPHONESIM
#	elif TARGET_OS_IPHONE
#		define QSC_SYSTEM_ISIPHONE
#	else
#		define QSC_SYSTEM_ISOSX
#	endif
#elif defined(__linux)
#	define QSC_SYSTEM_OS_LINUX
#elif defined(__unix)
#	define QSC_SYSTEM_OS_UNIX
#	if defined(__hpux) || defined(hpux)
#		define QSC_SYSTEM_OS_HPUX
#	endif
#	if defined(__sun__) || defined(__sun) || defined(sun)
#		define QSC_SYSTEM_OS_SUNUX
#	endif
#endif

/* cpu type (only intel/amd/arm are targeted for support) */
#if defined(QSC_SYSTEM_COMPILER_MSC)
#	if defined(_M_X64) || defined(_M_AMD64)
#		define QSC_SYSTEM_ARCH_X64
#		define QSC_SYSTEM_ARCH_X86_X64
#		if defined(_M_AMD64)
#			define QSC_SYSTEM_ARCH_AMD64
#		endif
#	elif defined(_M_IX86) || defined(_X86_)
#		define QSC_SYSTEM_ARCH_IX86
#		define QSC_SYSTEM_ARCH_X86_X64
#	elif defined(_M_ARM)
#		define QSC_SYSTEM_ARCH_ARM
#		if defined(_M_ARM_ARMV7VE)
#			define QSC_SYSTEM_ARCH_ARMV7VE
#		elif defined(_M_ARM_FP)
#			define QSC_SYSTEM_ARCH_ARMFP
#		elif defined(_M_ARM64)
#			define QSC_SYSTEM_ARCH_ARM64
#		endif
#	elif defined(_M_IA64)
#		define QSC_SYSTEM_ARCH_IA64
#	endif
#elif defined(QSC_SYSTEM_COMPILER_GCC)
#	if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64)
#		define QSC_SYSTEM_ARCH_X64
#		define QSC_SYSTEM_ARCH_X86_X64
#		if defined(_M_AMD64)
#			define QSC_SYSTEM_ARCH_AMD64
#		endif
#	elif defined(i386) || defined(__i386) || defined(__i386__)
#		define QSC_SYSTEM_ARCH_IX86
#		define QSC_SYSTEM_ARCH_X86_X64
#	elif defined(__arm__)
#		define QSC_SYSTEM_ARCH_ARM
#		if defined(__aarch64__)
#			define QSC_SYSTEM_ARCH_ARM64
#		endif
#	elif defined(__ia64) || defined(__ia64__) || defined(__itanium__)
#		define QSC_SYSTEM_ARCH_IA64
#	elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) || defined(__64BIT__) || defined(_LP64) || defined(__LP64__)
#		define QSC_SYSTEM_ARCH_PPC
#	elif defined(__sparc) || defined(__sparc__)
#		define QSC_SYSTEM_ARCH_SPARC
#		if defined(__sparc64__)
#			define QSC_SYSTEM_ARCH_SPARC64
#		endif
#	endif
#endif

// 32 or 64 bit architecture
#if (defined(__x86_64__) || defined(__amd64__) || defined(_M_X64))
#	define QSC_ARCH_64
#else
#	define QSC_ARCH_32
#endif

// network architecture
#if defined(_WIN64) || defined(_WIN32) || defined(__CYGWIN__)
#	define QSC_SYSTEM_WINDOWS_SOCKETS
#else
#	define QSC_SYSTEM_BERKELY_SOCKETS
#endif

#if !defined(__clang__) && !defined(__GNUC__)
#	ifdef __attribute__
#		undef __attribute__
#	endif
#	define __attribute__(a)
#endif

#if defined(_DLL)
#	define QSC_DLL_API
#endif

#if defined(QSC_DLL_API)
#	if defined(_MSC_VER)
#		if defined(QSC_DLL_IMPORT)
#			define QSC_EXPORT_API __declspec(dllimport)
#		else
#			define QSC_EXPORT_API __declspec(dllexport)
#		endif
#	else
#		if defined(__SUNPRO_C)
#			if !defined(__GNU_C__)
#				define QSC_EXPORT_API __attribute__ (visibility(__global))
#			else
#				define QSC_EXPORT_API __attribute__ __global
#			endif
#		elif defined(_MSG_VER)
#			define QSC_EXPORT_API extern __declspec(dllexport)
#		else
#			define QSC_EXPORT_API __attribute__ ((visibility ("default")))
#		endif
#	endif
#else
#	define QSC_EXPORT_API
#endif

#if defined(__GNUC__)
#	define QSC_CACHE_ALIGNED __attribute__((aligned(64)))
#elif defined(_MSC_VER)
#	define QSC_CACHE_ALIGNED __declspec(align(64))
#endif

#if defined(QSC_SYSTEM_ARCH_X64) || defined(QSC_SYSTEM_ARCH_ARM64) || defined(QSC_SYSTEM_ARCH_IA64) || defined(QSC_SYSTEM_ARCH_AMD64) || defined(QSC_SYSTEM_ARCH_ARM64) || defined(QSC_SYSTEM_ARCH_SPARC64)
#	define QSC_SYSTEM_IS_X64
#else
#	define QSC_SYSTEM_IS_X86
#endif

#if defined(QSC_SYSTEM_IS_X64)
#	define QSC_SIZE_MAX UINT64_MAX
#else
#	define QSC_SIZE_MAX UINT32_MAX
#endif

/* detect endianess */
#define QSC_SYSTEM_IS_LITTLE_ENDIAN (((union { uint32_t x; uint8_t c; }){1}).c)

/* define endianess of CPU */
#if (!defined(QSC_SYSTEM_IS_LITTLE_ENDIAN))
#	if defined(__sparc) || defined(__sparc__) || defined(__hppa__) || defined(__PPC__) || defined(__mips__) || defined(__MWERKS__) && (!defined(__INTEL__))
#		define QSC_SYSTEM_IS_BIG_ENDIAN
#	else
#		define QSC_SYSTEM_IS_LITTLE_ENDIAN
#	endif
#endif

#if !defined(__GNUC__)
#	if defined(__attribute__)
#		undef __attribute__
#	endif
#	define __attribute__(a)
#endif

// 128 bit unsigned integer support
#if defined(__SIZEOF_INT128__) && defined(QSC_SYSTEM_IS_X64) && !defined(__xlc__)
#	define QSC_SYSTEM_NATIVE_UINT128
	// Prefer TI mode over __int128 as GCC rejects the latter in pedantic mode
#	if defined(__GNUG__)
		typedef uint32_t uint128_t __attribute__((mode(TI)));
#	else
		typedef unsigned __int128 uint128_t;
#	endif
#endif

#if defined(QSC_SYSTEM_NATIVE_UINT128)
// functions 'borrowed' from Botan ;)
#	define QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)			\
	do {													\
      const uint128_t r = static_cast<uint128_t>(X) * Y;	\
      *High = (r >> 64) & 0xFFFFFFFFFFFFFFFFULL;			\
      *Low = (r) & 0xFFFFFFFFFFFFFFFFULL;					\
	} while(0)

#elif defined(QSC_SYSTEM_COMPILER_MSC) && defined(QSC_SYSTEM_IS_X64)
#	include <intrin.h>
#	pragma intrinsic(_umul128)
#	define QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)			\
	do {													\
		*Low = _umul128(X, Y, High);						\
	} while(0)

#elif defined(QSC_SYSTEM_COMPILER_GCC)
#	if defined(QSC_SYSTEM_ARCH_X86_X64)
#		define QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("mulq %3" : "=d" (*High), "=X" (*Low) : "X" (X), "rm" (Y) : "cc");	\
		} while(0)
#	elif defined(QSC_SYSTEM_ARCH_ALPHA)
#		define QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("umulh %1,%2,%0" : "=r" (*High) : "r" (X), "r" (Y));				\
		*Low = X * Y;															\
		} while(0)
#	elif defined(QSC_SYSTEM_ARCH_IA64)
#		define QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("xmpy.hu %0=%1,%2" : "=f" (*High) : "f" (X), "f" (Y));				\
		*Low = X * Y;															\
		} while(0)
#	elif defined(QSC_SYSTEM_ARCH_PPC)
#		define QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("mulhdu %0,%1,%2" : "=r" (*High) : "r" (X), "r" (Y) : "cc");		\
		*Low = X * Y;															\
		} while(0)
#	endif
#endif


#define QSC_SYSTEM_SECMEMALLOC_DEFAULT 4096
#define QSC_SYSTEM_SECMEMALLOC_MIN 16
#define QSC_SYSTEM_SECMEMALLOC_MAX 128
#define QSC_SYSTEM_SECMEMALLOC_MAXKB 512

#if defined(_WIN32)
#	define QSC_SYSTEM_HAS_VIRTUALLOCK
#	define QSC_HAS_RTLSECUREMEMORY
#endif

#if defined(__posix) || defined(_POSIX_VERSION)
#	define QSC_SYSTEM_OS_POSIX
#	include <unistd.h>
#endif

#if defined(_POSIX_MEMLOCK_RANGE)
#	define QSC_SYSTEM_HAS_POSIXMLOCK
#endif

// the secure allocator is enabled
#if defined(QSC_SYSTEM_HAS_VIRTUALLOCK) || defined(QSC_SYSTEM_HAS_POSIXMLOCK)
#	define QSC_SYSTEM_SECURE_ALLOCATOR
#endif

#define QSC_SYSTEM_STRHELPER(x) #x
#define QSC_SYSTEM_TO_STRING(x) QSC_SYSTEM_STRHELPER(x)

// instructs the compiler to skip optimizations on the contained function; closed with CEX_OPTIMIZE_RESUME 
#if defined(QSC_SYSTEM_COMPILER_MSC)
#	define QSC_SYSTEM_OPTIMIZE_IGNORE __pragma(optimize("", off))
#elif defined(QSC_SYSTEM_COMPILER_GCC) || defined(QSC_SYSTEM_COMPILER_MINGW)
	_Pragma(QSC_SYSTEM_TO_STRING(GCC optimize("O0")))
#	define QSC_SYSTEM_TO_STRING #pragma GCC optimize ("O0"), #pragma GCC optimize ("O0")
#elif defined(QSC_SYSTEM_COMPILER_CLANG)
#	define QSC_SYSTEM_OPTIMIZE_IGNORE __attribute__((optnone))
#elif defined(QSC_SYSTEM_COMPILER_INTEL)
#	define QSC_SYSTEM_OPTIMIZE_IGNORE pragma optimize("", off) 
#else
#	define QSC_SYSTEM_OPTIMIZE_IGNORE 0
#endif

// end of section; resume compiler optimizations 
#if defined(QSC_SYSTEM_COMPILER_MSC)
#	define QSC_SYSTEM_OPTIMIZE_RESUME __pragma(optimize("", on))
#elif defined(QSC_SYSTEM_COMPILER_GCC) || defined(QSC_SYSTEM_COMPILER_MINGW)
//	_Pragma(QSC_SYSTEM_TO_STRING(GCC pop_options))
#	define QSC_SYSTEM_OPTIMIZE_RESUME #pragma GCC pop_options
#elif defined(CEX_COMPILER_INTEL)
#	define QSC_SYSTEM_OPTIMIZE_RESUME pragma optimize("", on) 
#else
#	define QSC_SYSTEM_OPTIMIZE_RESUME 0
#endif

/* intrinsics support level */

#if _MSC_VER >= 1600
#	define QSC_WMMINTRIN_H 1
#endif
#if _MSC_VER >= 1700 && defined(_M_X64)
#	define QSC_HAVE_AVX2INTRIN_H 1
#endif

/*
* AVX512 Capabilities Check
* TODO: future expansion (if you can test it, I'll add it)
* links: 
* https://software.intel.com/en-us/intel-cplusplus-compiler-16.0-user-and-reference-guide
* https://software.intel.com/en-us/articles/compiling-for-the-intel-xeon-phi-processor-and-the-intel-avx-512-isa
* https://colfaxresearch.com/knl-avx512/
* 
* #include <immintrin.h>
* supported is 1: ex. __AVX512CD__ 1
* F		__AVX512F__					Foundation
* CD	__AVX512CD__				Conflict Detection Instructions(CDI)
* ER	__AVX512ER__				Exponential and Reciprocal Instructions(ERI)
* PF	__AVX512PF__				Prefetch Instructions(PFI)
* DQ	__AVX512DQ__				Doubleword and Quadword Instructions(DQ)
* BW	__AVX512BW__				Byte and Word Instructions(BW)
* VL	__AVX512VL__				Vector Length Extensions(VL)
* IFMA	__AVX512IFMA__				Integer Fused Multiply Add(IFMA)
* VBMI	__AVX512VBMI__				Vector Byte Manipulation Instructions(VBMI)
* VNNIW	__AVX5124VNNIW__			Vector instructions for deep learning enhanced word variable precision
* FMAPS	__AVX5124FMAPS__			Vector instructions for deep learning floating - point single precision
* VPOPCNT	__AVX512VPOPCNTDQ__		?
* 
* Note: AVX512 is currently untested, this flag enables support on a compliant system
*/

/* Enable this define to support AVX512 on a compatible system */
//#define CEX_AVX512_SUPPORTED

#if defined(__AVX512F__) && (__AVX512F__ == 1)
#	include <immintrin.h>
#	if (!defined(__AVX512__))
#		define __AVX512__
#	endif
#endif

#if defined(__SSE2__)
#	define QSC_SYSTEM_HAS_SSE2
#endif
#if defined(__SSE3__)
#	define QSC_SYSTEM_HAS_SSE3
#endif
#if defined(__SSSE3__)
#	define QSC_SYSTEM_HAS_SSSE3
#endif
#if defined(__SSE4_1__)
#	define QSC_SYSTEM_HAS_SSE41
#endif
#if defined(__SSE4_2__)
#	define QSC_SYSTEM_HAS_SSE42
#endif
#if defined(__AVX__)
#	define QSC_SYSTEM_HAS_AVX
#endif
#if defined(__AVX2__)
#	define QSC_SYSTEM_HAS_AVX2
#endif
#if defined(__AVX512__)
#	define QSC_SYSTEM_HAS_AVX512
#endif
#if defined(__XOP__)
#	define QSC_SYSTEM_HAS_XOP
#endif

#if defined(__AVX__) || defined(__AVX2__) || defined(__AVX512__)
#	define QSC_SYSTEM_AVX_INTRINSICS
#endif

/*!
\def QSC_STATUS_SUCCESS
* Function return value indicates successful operation
*/
#define QSC_STATUS_SUCCESS 0

/*!
\def QSC_STATUS_FAILURE
* Function return value indicates failed operation
*/
#define QSC_STATUS_FAILURE -1

/*!
\def QSC_ERROR_AUTHENTICATION
* Function return value indicates internal failure
*/
#define QSC_ERROR_INTERNAL -2

/*!
\def QSC_ERROR_AUTHENTICATION
* Function return value indicates authntication failure
*/
#define QSC_ERROR_AUTHENTICATION -3

/*!
\def QSC_ERROR_PROVIDER
* Function return value indicates a random provider failure
*/
#define QSC_ERROR_PROVIDER -4


/* Modifiable values that determine which parameter sets and options get compiled */

/*!
\def QSC_SYSTEM_AESNI_ENABLED
* Enable if AESNI instructions are available on the target system
*/
//#define QSC_SYSTEM_AESNI_ENABLED

/*!
* \def QSC_KECCAK_UNROLLED_PERMUTATION
* \brief Define to use the UNROLLED form of the keccak permutation function
* if undefined, functions use the compact form of the keccak permutation
*/
//#define QSC_KECCAK_UNROLLED_PERMUTATION

/*** McEliece ***/

/*!
\def QSC_MCELIECE_N6960T119
* Implement the McEliece N6960T119 parameter set
*/
#define QSC_MCELIECE_N6960T119

/*!
\def QSC_MCELIECE_N8192T128
* Implement the McEliece N8192T128 parameter set
*/
//#define QSC_MCELIECE_N8192T128


/*** Kyber ***/

/*!
\def QSC_KYBER_S1Q3329N256
* Implement the Kyber S1Q3329N256 parameter set
*/
//#define QSC_KYBER_S1Q3329N256

/*!
\def QSC_KYBER_S2Q3329N256
* Implement the Kyber S2Q3329N256 parameter set
*/
#define QSC_KYBER_S2Q3329N256

/*!
\def QSC_KYBER_S3Q3329N256
* Implement the Kyber S3Q3329N256 parameter set
*/
//#define QSC_KYBER_S3Q3329N256


/*** ECDH ***/

/*!
\def QSC_ECDH_S1EC25519
* Implement the ECDH S1EC25519 parameter set
*/
#define QSC_ECDH_S1EC25519


/*** Dilithium ***/

/*!
\def QSC_DILITHIUM_S1N256Q8380417
* Implement the Dilithium S1N256Q8380417 parameter set
*/
//#define QSC_DILITHIUM_S1N256Q8380417

/*!
\def QSC_DILITHIUM_S2N256Q8380417
* Implement the Dilithium S2N256Q8380417 parameter set
*/
#define QSC_DILITHIUM_S2N256Q8380417

/*!
\def QSC_DILITHIUM_S3N256Q8380417
* Implement the Dilithium S3N256Q8380417 parameter set
*/
//#define QSC_DILITHIUM_S3N256Q8380417


/*** SphincsPlus ***/

/*!
\def QSC_SPHINCSPLUS_S1S128SHAKE
* Implement the SphincsPlus S1S128SHAKE parameter set
*/
#define QSC_SPHINCSPLUS_S1S128SHAKE

/*!
\def QSC_SPHINCSPLUS_S2S192SHAKE
* Implement the SphincsPlus S2S192SHAKE parameter set
*/
//#define QSC_SPHINCSPLUS_S2S192SHAKE

/*!
\def QSC_SPHINCSPLUS_S3S256SHAKE
* Implement the SphincsPlus S3S256SHAKE parameter set
*/
//#define QSC_SPHINCSPLUS_S3S256SHAKE


/*** ECDSA ***/

/*!
\def QSC_ECDSA_S1EC25519
* Implement the ECDSA S1EC25519 parameter set
*/
#define QSC_ECDSA_S1EC25519

#endif
