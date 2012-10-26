/*
 * sha3.c: routines to compute SHA-3 digests
 *
 * Ref: http://keccak.noekeon.org/specs_summary.html
 *
 * Copyright (C) 2012 Mark Shelor, All Rights Reserved
 *
 * Version: 0.01
 * Wed Oct 24 13:05:18 MST 2012
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include "sha3.h"

#define UCHR	unsigned char		/* useful abbreviations */
#define UINT	unsigned int
#define ULNG	unsigned long
#define VP	void *
#define W64	SHA64
#define C64	SHA64_CONST
#define SR64	SHA64_SHR
#define SL64	SHA64_SHL

#define A5(v)	{v, v, v, v, v}

/* mem2word: convert little-endian to 64-bit value */
static W64 mem2word(unsigned char *mem)
{
	unsigned char *p;
	W64 w = 0;

	for (p = mem+7; p >= mem;)
		w = (w << 8) | *p--;
	return(w);
}

/* word2mem: write 64-bit value in little-endian order */
static unsigned char *word2mem(W64 w, unsigned char *mem)
{
	int i;
	unsigned char *p = mem;

	for (i = 0; i < 8; i++, w >>= 8)
		*p++ = w & 0xff;
	return(mem);
}

static W64 RC[] = {		/* Keccak round constants */
C64(0x0000000000000001), C64(0x0000000000008082), C64(0x800000000000808a),
C64(0x8000000080008000), C64(0x000000000000808b), C64(0x0000000080000001),
C64(0x8000000080008081), C64(0x8000000000008009), C64(0x000000000000008a),
C64(0x0000000000000088), C64(0x0000000080008009), C64(0x000000008000000a),
C64(0x000000008000808b), C64(0x800000000000008b), C64(0x8000000000008089),
C64(0x8000000000008003), C64(0x8000000000008002), C64(0x8000000000000080),
C64(0x000000000000800a), C64(0x800000008000000a), C64(0x8000000080008081),
C64(0x8000000000008080), C64(0x0000000080000001), C64(0x8000000080008008)
};

static int R[][5] = {		/* Keccak rotation offsets */
	{0,  36,  3, 41, 18}, {1,  44, 10, 45,  2}, {62,  6, 43, 15, 61},
	{28, 55, 25, 21, 56}, {27, 20, 39,  8, 14}
};

/* rot: rotate 64-bit word left by n bit positions */
#define rot(w, n) (SR64((w), (64 - (n))) | SL64((w), (n)))

/* keccak_f: apply KECCAK-f[1600] permutation for 24 rounds */
static void keccak_f(W64 A[][5])
{
	int i, x, y;
	for (i = 0; i < 24; i++) {
		W64 B[5][5] = A5(A5(0));
		W64 C[5] = A5(0);
		W64 D[5] = A5(0);
		for (x = 0; x < 5; x++)
			C[x] = A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4];
		for (x = 0; x < 5; x++)
			D[x] = C[(x+4)%5] ^ rot(C[(x+1)%5], 1);
		for (x = 0; x < 5; x++)
			for (y = 0; y < 5; y++)
				A[x][y] = A[x][y] ^ D[x];
		for (x = 0; x < 5; x++)
			for (y = 0; y < 5; y++)
				B[y][(2*x+3*y)%5] = rot(A[x][y], R[x][y]);
		for (x = 0; x < 5; x++)
			for (y = 0; y < 5; y++)
				A[x][y] = B[x][y] ^ ((~B[(x+1)%5][y]) &
							B[(x+2)%5][y]);
		A[0][0] = A[0][0] ^ RC[i];
	}
}

/* sha3: update SHA3 state with one block of data */
static void sha3(SHA3 *s, UCHR *block)
{
	int i, x, y;
	int N = s->blocksize/64;
	W64 P0[5][5] = A5(A5(0));

	for (i = 0; i < N; i++)
		P0[i%5][i/5] = mem2word(block+i*8);
	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++) {
			if (x + y*5 >= N)
				break;
			s->S[x][y] = s->S[x][y] ^ P0[x][y];
		}
	keccak_f(s->S);
}

/* digcpy: write final SHA3 state to digest buffer */
static void digcpy(SHA3 *s)
{
	int x, y;
	int N = s->blocksize/64;
	UCHR *Z = s->digest;
	int outbits = s->digestlen*8;

	while (outbits > 0) {
		for (y = 0; y < 5; y++)
			for (x = 0; x < 5; x++) {
				if (x + y*5 >= N)
					break;
				word2mem(s->S[x][y], Z);
				Z += 8;
			}
		if ((outbits -= s->blocksize) > 0)
			keccak_f(s->S);
	}
}

#define SETBIT(s, pos)	s[(pos) >> 3] |=  (0x01 << (7 - (pos) % 8))
#define CLRBIT(s, pos)	s[(pos) >> 3] &= ~(0x01 << (7 - (pos) % 8))
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
		alg != SHA3_384    && alg != SHA3_512)
		return(NULL);
	SHA_newz(0, s, 1, SHA3);
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
	UCHR b;

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

	SHA_new(0, p, 1, SHA3);
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
		SHA_free(s);
	}
	return(0);
}
