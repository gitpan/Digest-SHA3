/*
 * sha3.h: header file for SHA-3 routines
 *
 * Ref: http://keccak.noekeon.org/specs_summary.html
 *
 * Copyright (C) 2012 Mark Shelor, All Rights Reserved
 *
 * Version: 0.03
 * Mon Oct 29 04:01:06 MST 2012
 *
 */

#ifndef _INCLUDE_SHA3_H_
#define _INCLUDE_SHA3_H_

#include <limits.h>

#define SHA64_SHR(x, n)	((x) >> (n))
#define SHA64_SHL(x, n)	((x) << (n))

#define SHA64_ALIGNED

#if defined(ULONG_LONG_MAX) || defined(ULLONG_MAX) || defined(HAS_LONG_LONG)
	#define SHA_ULL_EXISTS
#endif

#if (((ULONG_MAX >> 16) >> 16) >> 16) >> 15 == 1UL
	#define SHA64	unsigned long
	#define SHA64_CONST(c)	c ## UL
#elif defined(SHA_ULL_EXISTS) && defined(LONGLONGSIZE) && LONGLONGSIZE == 8
	#define SHA64	unsigned long long
	#define SHA64_CONST(c)	c ## ULL
#elif defined(SHA_ULL_EXISTS)
	#undef  SHA64_ALIGNED
	#undef  SHA64_SHR
	#define SHA64_MAX	18446744073709551615ULL
	#define SHA64_SHR(x, n)	(((x) & SHA64_MAX) >> (n))
	#define SHA64	unsigned long long
	#define SHA64_CONST(c)	c ## ULL

	/* The following cases detect compilers that
	 * support 64-bit types in a non-standard way */

#elif defined(_MSC_VER)					/* Microsoft C */
	#define SHA64	unsigned __int64
	#define SHA64_CONST(c)	(SHA64) c
#endif

#define SHA3_new		New
#define SHA3_newz		Newz
#define SHA3_free		Safefree
#define SHA3_FILE		PerlIO
#define SHA3_stdin()		PerlIO_stdin()
#define SHA3_stdout()		PerlIO_stdout()
#define SHA3_open		PerlIO_open
#define SHA3_close		PerlIO_close
#define SHA3_fprintf		PerlIO_printf
#define SHA3_feof		PerlIO_eof
#define SHA3_getc		PerlIO_getc

#define SHA3_0		0
#define SHA3_224	224
#define SHA3_256	256
#define SHA3_384	384
#define SHA3_512	512

#define SHA3_0_BLOCK_BITS	1024
#define SHA3_224_BLOCK_BITS	1152
#define SHA3_256_BLOCK_BITS	1088
#define SHA3_384_BLOCK_BITS	832
#define SHA3_512_BLOCK_BITS	576

#define SHA3_0_DIGEST_BITS	4096
#define SHA3_224_DIGEST_BITS	224
#define SHA3_256_DIGEST_BITS	256
#define SHA3_384_DIGEST_BITS	384
#define SHA3_512_DIGEST_BITS	512

#define SHA3_MAX_BLOCK_BITS	SHA3_224_BLOCK_BITS
#define SHA3_MAX_DIGEST_BITS	SHA3_0_DIGEST_BITS
#define SHA3_MAX_HEX_LEN	(SHA3_MAX_DIGEST_BITS / 4)
#define SHA3_MAX_BASE64_LEN	(1 + (SHA3_MAX_DIGEST_BITS / 6))

typedef struct SHA3 {
	int alg;
	SHA64 S[5][5];
	unsigned char block[SHA3_MAX_BLOCK_BITS/8];
	unsigned int blockcnt;
	unsigned int blocksize;
	unsigned char digest[SHA3_MAX_DIGEST_BITS/8];
	int digestlen;
	char hex[SHA3_MAX_HEX_LEN+1];
	char base64[SHA3_MAX_BASE64_LEN+1];
} SHA3;

#define _SHA3_STATE	SHA3 *s
#define _SHA3_ALG	int alg
#define _SHA3_DATA	unsigned char *bitstr, unsigned long bitcnt
#define _SHA3_FNAME	char *filename

SHA3		*shaopen	(_SHA3_ALG);
unsigned long	 shawrite	(_SHA3_DATA, _SHA3_STATE);
void		 shafinish	(_SHA3_STATE);
void		 sharewind	(_SHA3_STATE);
unsigned char	*shadigest	(_SHA3_STATE);
char		*shahex		(_SHA3_STATE);
char		*shabase64	(_SHA3_STATE);
int		 shadsize	(_SHA3_STATE);
int		 shaalg		(_SHA3_STATE);
SHA3		*shadup		(_SHA3_STATE);
int		 shaclose	(_SHA3_STATE);

#endif	/* _INCLUDE_SHA3_H_ */
