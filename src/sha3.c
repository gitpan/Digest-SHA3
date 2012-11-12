/*
 * sha3.c: routines to compute SHA-3 digests
 *
 * Ref: http://keccak.noekeon.org/specs_summary.html
 *
 * Copyright (C) 2012 Mark Shelor, All Rights Reserved
 *
 * Version: 0.04
 * Sun Nov 11 19:20:06 MST 2012
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "sha3.h"

#define UCHR	unsigned char		/* useful abbreviations */
#define UINT	unsigned int
#define ULNG	unsigned long
#define W64	SHA64
#define C64	SHA64_CONST
#define SR64	SHA64_SHR
#define SL64	SHA64_SHL

/* word2mem: write 64-bit value in little-endian order */
static UCHR *word2mem(W64 w, UCHR *mem)
{
	int i;
	UCHR *p = mem;

	for (i = 0; i < 8; i++, w >>= 8)
		*p++ = w & 0xff;
	return(mem);
}

static W64 RC[] = {	/* Keccak round constants */
	C64(0x0000000000000001), C64(0x0000000000008082),
	C64(0x800000000000808a), C64(0x8000000080008000),
	C64(0x000000000000808b), C64(0x0000000080000001),
	C64(0x8000000080008081), C64(0x8000000000008009),
	C64(0x000000000000008a), C64(0x0000000000000088),
	C64(0x0000000080008009), C64(0x000000008000000a),
	C64(0x000000008000808b), C64(0x800000000000008b),
	C64(0x8000000000008089), C64(0x8000000000008003),
	C64(0x8000000000008002), C64(0x8000000000000080),
	C64(0x000000000000800a), C64(0x800000008000000a),
	C64(0x8000000080008081), C64(0x8000000000008080),
	C64(0x0000000080000001), C64(0x8000000080008008)
};

/* ROTL: rotate 64-bit word left by n bit positions */
#define ROTL(w, n) (SR64((w), (64 - (n))) | SL64((w), (n)))

/* keccak_f: apply KECCAK-f[1600] permutation for 24 rounds */
static void keccak_f(W64 A[][5])
{
	int i;
	W64 *rc = RC;
	for (i = 0; i < 24; i++, rc++) {
		W64 B[5][5], C[5], D[5];
		C[0] = A[0][0]^A[0][1]^A[0][2]^A[0][3]^A[0][4];
		C[1] = A[1][0]^A[1][1]^A[1][2]^A[1][3]^A[1][4];
		C[2] = A[2][0]^A[2][1]^A[2][2]^A[2][3]^A[2][4];
		C[3] = A[3][0]^A[3][1]^A[3][2]^A[3][3]^A[3][4];
		C[4] = A[4][0]^A[4][1]^A[4][2]^A[4][3]^A[4][4];
		D[0] = C[4] ^ ROTL(C[1], 1);
		D[1] = C[0] ^ ROTL(C[2], 1);
		D[2] = C[1] ^ ROTL(C[3], 1);
		D[3] = C[2] ^ ROTL(C[4], 1);
		D[4] = C[3] ^ ROTL(C[0], 1);
		A[0][0] ^= D[0];
		A[0][1] ^= D[0];
		A[0][2] ^= D[0];
		A[0][3] ^= D[0];
		A[0][4] ^= D[0];
		A[1][0] ^= D[1];
		A[1][1] ^= D[1];
		A[1][2] ^= D[1];
		A[1][3] ^= D[1];
		A[1][4] ^= D[1];
		A[2][0] ^= D[2];
		A[2][1] ^= D[2];
		A[2][2] ^= D[2];
		A[2][3] ^= D[2];
		A[2][4] ^= D[2];
		A[3][0] ^= D[3];
		A[3][1] ^= D[3];
		A[3][2] ^= D[3];
		A[3][3] ^= D[3];
		A[3][4] ^= D[3];
		A[4][0] ^= D[4];
		A[4][1] ^= D[4];
		A[4][2] ^= D[4];
		A[4][3] ^= D[4];
		A[4][4] ^= D[4];
		B[0][0] = A[0][0];
		B[1][3] = ROTL(A[0][1], 36);
		B[2][1] = ROTL(A[0][2], 3);
		B[3][4] = ROTL(A[0][3], 41);
		B[4][2] = ROTL(A[0][4], 18);
		B[0][2] = ROTL(A[1][0], 1);
		B[1][0] = ROTL(A[1][1], 44);
		B[2][3] = ROTL(A[1][2], 10);
		B[3][1] = ROTL(A[1][3], 45);
		B[4][4] = ROTL(A[1][4], 2);
		B[0][4] = ROTL(A[2][0], 62);
		B[1][2] = ROTL(A[2][1], 6);
		B[2][0] = ROTL(A[2][2], 43);
		B[3][3] = ROTL(A[2][3], 15);
		B[4][1] = ROTL(A[2][4], 61);
		B[0][1] = ROTL(A[3][0], 28);
		B[1][4] = ROTL(A[3][1], 55);
		B[2][2] = ROTL(A[3][2], 25);
		B[3][0] = ROTL(A[3][3], 21);
		B[4][3] = ROTL(A[3][4], 56);
		B[0][3] = ROTL(A[4][0], 27);
		B[1][1] = ROTL(A[4][1], 20);
		B[2][4] = ROTL(A[4][2], 39);
		B[3][2] = ROTL(A[4][3], 8);
		B[4][0] = ROTL(A[4][4], 14);
		A[0][0] = B[0][0] ^ (~B[1][0] & B[2][0]);
		A[0][1] = B[0][1] ^ (~B[1][1] & B[2][1]);
		A[0][2] = B[0][2] ^ (~B[1][2] & B[2][2]);
		A[0][3] = B[0][3] ^ (~B[1][3] & B[2][3]);
		A[0][4] = B[0][4] ^ (~B[1][4] & B[2][4]);
		A[1][0] = B[1][0] ^ (~B[2][0] & B[3][0]);
		A[1][1] = B[1][1] ^ (~B[2][1] & B[3][1]);
		A[1][2] = B[1][2] ^ (~B[2][2] & B[3][2]);
		A[1][3] = B[1][3] ^ (~B[2][3] & B[3][3]);
		A[1][4] = B[1][4] ^ (~B[2][4] & B[3][4]);
		A[2][0] = B[2][0] ^ (~B[3][0] & B[4][0]);
		A[2][1] = B[2][1] ^ (~B[3][1] & B[4][1]);
		A[2][2] = B[2][2] ^ (~B[3][2] & B[4][2]);
		A[2][3] = B[2][3] ^ (~B[3][3] & B[4][3]);
		A[2][4] = B[2][4] ^ (~B[3][4] & B[4][4]);
		A[3][0] = B[3][0] ^ (~B[4][0] & B[0][0]);
		A[3][1] = B[3][1] ^ (~B[4][1] & B[0][1]);
		A[3][2] = B[3][2] ^ (~B[4][2] & B[0][2]);
		A[3][3] = B[3][3] ^ (~B[4][3] & B[0][3]);
		A[3][4] = B[3][4] ^ (~B[4][4] & B[0][4]);
		A[4][0] = B[4][0] ^ (~B[0][0] & B[1][0]);
		A[4][1] = B[4][1] ^ (~B[0][1] & B[1][1]);
		A[4][2] = B[4][2] ^ (~B[0][2] & B[1][2]);
		A[4][3] = B[4][3] ^ (~B[0][3] & B[1][3]);
		A[4][4] = B[4][4] ^ (~B[0][4] & B[1][4]);
		A[0][0] ^= *rc;
	}
}

/* sha3: update SHA3 state with one block of data */
static void sha3(SHA3 *s, UCHR *block)
{
	int i, x, y;
	W64 P0[5][5];

	for (i = 0; i < s->blocksize/64; i++, block += 8)
		MEM2WORD(&P0[i%5][i/5], block);
	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++) {
			if (x + y*5 >= s->blocksize/64)
				break;
			s->S[x][y] ^= P0[x][y];
		}
	keccak_f(s->S);
}

/* digcpy: write final SHA3 state to digest buffer */
static void digcpy(SHA3 *s)
{
	int x, y;
	UCHR *Z = s->digest;
	int outbits = s->digestlen*8;

	while (outbits > 0) {
		for (y = 0; y < 5; y++)
			for (x = 0; x < 5; x++, Z += 8) {
				if (x + y*5 >= s->blocksize/64)
					break;
				word2mem(s->S[x][y], Z);
			}
		if ((outbits -= s->blocksize) > 0)
			keccak_f(s->S);
	}
}

#define NBYTES(nbits)   (((nbits) + 7) >> 3)
#define HEXLEN(nbytes)	((nbytes) << 1)
#define B64LEN(nbytes)	(((nbytes) % 3 == 0) ? ((nbytes) / 3) * 4 \
			: ((nbytes) / 3) * 4 + ((nbytes) % 3) + 1)

#define SHA3_INIT(algo)							\
	do {								\
		memset(s, 0, sizeof(SHA3));				\
		s->alg = algo;						\
		s->blocksize = SHA3_ ## algo ## _BLOCK_BITS;		\
		s->digestlen = SHA3_ ## algo ## _DIGEST_BITS >> 3;	\
	} while (0)

/* sharewind: re-initializes the digest object */
void sharewind(SHA3 *s)
{
	if      (s->alg == SHA3_0)   SHA3_INIT(0);
	else if (s->alg == SHA3_224) SHA3_INIT(224);
	else if (s->alg == SHA3_256) SHA3_INIT(256);
	else if (s->alg == SHA3_384) SHA3_INIT(384);
	else if (s->alg == SHA3_512) SHA3_INIT(512);
}

/* shaopen: creates a new digest object */
SHA3 *shaopen(int alg)
{
	SHA3 *s;

	if (alg != SHA3_0 && alg != SHA3_224 && alg != SHA3_256 &&
		alg != SHA3_384 && alg != SHA3_512)
		return(NULL);
	SHA3_newz(0, s, 1, SHA3);
	if (s == NULL)
		return(NULL);
	s->alg = alg;
	sharewind(s);
	return(s);
}

/* shadirect: updates state directly (w/o going through s->block) */
static ULNG shadirect(UCHR *bitstr, ULNG bitcnt, SHA3 *s)
{
	ULNG savecnt = bitcnt;

	while (bitcnt >= s->blocksize) {
		sha3(s, bitstr);
		bitstr += (s->blocksize >> 3);
		bitcnt -= s->blocksize;
	}
	if (bitcnt > 0) {
		memcpy(s->block, bitstr, NBYTES(bitcnt));
		s->blockcnt = bitcnt;
	}
	return(savecnt);
}

/* shabytes: updates state for byte-aligned input data */
static ULNG shabytes(UCHR *bitstr, ULNG bitcnt, SHA3 *s)
{
	UINT offset;
	UINT nbits;
	ULNG savecnt = bitcnt;

	offset = s->blockcnt >> 3;
	if (s->blockcnt + bitcnt >= s->blocksize) {
		nbits = s->blocksize - s->blockcnt;
		memcpy(s->block+offset, bitstr, nbits>>3);
		bitcnt -= nbits;
		bitstr += (nbits >> 3);
		sha3(s, s->block), s->blockcnt = 0;
		shadirect(bitstr, bitcnt, s);
	}
	else {
		memcpy(s->block+offset, bitstr, NBYTES(bitcnt));
		s->blockcnt += bitcnt;
	}
	return(savecnt);
}

/* shabits: updates state for bit-aligned input data */
static ULNG shabits(UCHR *bitstr, ULNG bitcnt, SHA3 *s)
{
	UINT i;
	UINT gap;
	ULNG nbits;
	UCHR buf[1<<9];
	UINT bufsize = sizeof(buf);
	ULNG bufbits = (ULNG) bufsize << 3;
	UINT nbytes = NBYTES(bitcnt);
	ULNG savecnt = bitcnt;

	gap = 8 - s->blockcnt % 8;
	s->block[s->blockcnt>>3] &= ~0 << gap;
	s->block[s->blockcnt>>3] |= *bitstr >> (8 - gap);
	s->blockcnt += bitcnt < gap ? bitcnt : gap;
	if (bitcnt < gap)
		return(savecnt);
	if (s->blockcnt == s->blocksize)
		sha3(s, s->block), s->blockcnt = 0;
	if ((bitcnt -= gap) == 0)
		return(savecnt);
	while (nbytes > bufsize) {
		for (i = 0; i < bufsize; i++)
			buf[i] = bitstr[i] << gap | bitstr[i+1] >> (8-gap);
		nbits = bitcnt < bufbits ? bitcnt : bufbits;
		shabytes(buf, nbits, s);
		bitcnt -= nbits, bitstr += bufsize, nbytes -= bufsize;
	}
	for (i = 0; i < nbytes - 1; i++)
		buf[i] = bitstr[i] << gap | bitstr[i+1] >> (8-gap);
	buf[nbytes-1] = bitstr[nbytes-1] << gap;
	shabytes(buf, bitcnt, s);
	return(savecnt);
}

/* shawrite: triggers a state update using data in bitstr/bitcnt */
ULNG shawrite(UCHR *bitstr, ULNG bitcnt, SHA3 *s)
{
	if (bitcnt < 1)
		return(0);
	if (s->blockcnt == 0)
		return(shadirect(bitstr, bitcnt, s));
	else if (s->blockcnt % 8 == 0)
		return(shabytes(bitstr, bitcnt, s));
	else
		return(shabits(bitstr, bitcnt, s));
}

/* shafinish: pads remaining block(s) and computes final digest state */
void shafinish(SHA3 *s)
{
	UCHR b;		/* partial byte */

	if (s->blockcnt % 8 == 0) {
		s->block[s->blockcnt/8] = 0x01, s->blockcnt += 8;
		while (s->blockcnt < s->blocksize)
			s->block[s->blockcnt/8] = 0x00, s->blockcnt += 8;
		s->block[(s->blockcnt/8)-1] |= 0x80;
		sha3(s, s->block);
		return;
	}
	b = 0x80 | (s->block[NBYTES(s->blockcnt)-1] >> 1);
	s->blockcnt++;
	if (s->blockcnt % 8 == 0) {
		s->block[(s->blockcnt/8)-1] = b;
		if (s->blockcnt == s->blocksize)
			sha3(s, s->block), s->blockcnt = 0;
		s->block[s->blockcnt/8] = 0x00, s->blockcnt += 8;
	}
	else {
		while (s->blockcnt % 8)
			b >>= 1, s->blockcnt++;
		s->block[(s->blockcnt/8)-1] = b;
	}
	while (s->blockcnt % s->blocksize)
		s->block[s->blockcnt/8] = 0x00, s->blockcnt += 8;
	s->block[(s->blockcnt/8)-1] |= 0x80;
	sha3(s, s->block);
}

/* shadigest: returns pointer to current digest (binary) */
UCHR *shadigest(SHA3 *s)
{
	digcpy(s);
	return(s->digest);
}

/* shahex: returns pointer to current digest (hexadecimal) */
char *shahex(SHA3 *s)
{
	int i;

	digcpy(s);
	s->hex[0] = '\0';
	if (HEXLEN((size_t) s->digestlen) >= sizeof(s->hex))
		return(s->hex);
	for (i = 0; i < s->digestlen; i++)
		sprintf(s->hex+i*2, "%02x", s->digest[i]);
	return(s->hex);
}

/* map: translation map for Base 64 encoding */
static char map[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* encbase64: encodes input (0 to 3 bytes) into Base 64 */
static void encbase64(UCHR *in, int n, char *out)
{
	UCHR byte[3] = {0, 0, 0};

	out[0] = '\0';
	if (n < 1 || n > 3)
		return;
	memcpy(byte, in, n);
	out[0] = map[byte[0] >> 2];
	out[1] = map[((byte[0] & 0x03) << 4) | (byte[1] >> 4)];
	out[2] = map[((byte[1] & 0x0f) << 2) | (byte[2] >> 6)];
	out[3] = map[byte[2] & 0x3f];
	out[n+1] = '\0';
}

/* shabase64: returns pointer to current digest (Base 64) */
char *shabase64(SHA3 *s)
{
	int n;
	UCHR *q;
	char out[5];

	digcpy(s);
	s->base64[0] = '\0';
	if (B64LEN(s->digestlen) >= sizeof(s->base64))
		return(s->base64);
	for (n = s->digestlen, q = s->digest; n > 3; n -= 3, q += 3) {
		encbase64(q, 3, out);
		strcat(s->base64, out);
	}
	encbase64(q, n, out);
	strcat(s->base64, out);
	return(s->base64);
}

/* shadsize: returns length of digest in bytes */
int shadsize(SHA3 *s)
{
	return(s->digestlen);
}

/* shaalg: returns which SHA-3 algorithm is being used */
int shaalg(SHA3 *s)
{
	return(s->alg);
}

/* shadup: duplicates current digest object */
SHA3 *shadup(SHA3 *s)
{
	SHA3 *p;

	SHA3_new(0, p, 1, SHA3);
	if (p == NULL)
		return(NULL);
	memcpy(p, s, sizeof(SHA3));
	return(p);
}

/* shaclose: de-allocates digest object */
int shaclose(SHA3 *s)
{
	if (s != NULL) {
		memset(s, 0, sizeof(SHA3));
		SHA3_free(s);
	}
	return(0);
}
