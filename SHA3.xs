#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#ifdef SvPVbyte
	#if PERL_REVISION == 5 && PERL_VERSION < 8
		#undef SvPVbyte
		#define SvPVbyte(sv, lp) \
			(sv_utf8_downgrade((sv), 0), SvPV((sv), (lp)))
	#endif
#else
	#define SvPVbyte SvPV
#endif

#include "src/sha3.c"

static int ix2alg[] =
	{0,0,0,224,224,224,256,256,256,384,384,384,512,512,512};

MODULE = Digest::SHA3		PACKAGE = Digest::SHA3

PROTOTYPES: ENABLE

#ifndef INT2PTR
#define INT2PTR(p, i) (p) (i)
#endif

#define MAX_WRITE_SIZE 16384

int
shaclose(s)
	SHA3 *	s

SHA3 *
shadup(s)
	SHA3 *	s

SHA3 *
shaopen(alg)
	int	alg

void
sharewind(s)
	SHA3 *	s

unsigned long
shawrite(bitstr, bitcnt, s)
	unsigned char *	bitstr
	unsigned long	bitcnt
	SHA3 *	s

void
sha3_0(...)
ALIAS:
	Digest::SHA3::sha3_0 = 0
	Digest::SHA3::sha3_0_hex = 1
	Digest::SHA3::sha3_0_base64 = 2
	Digest::SHA3::sha3_224 = 3
	Digest::SHA3::sha3_224_hex = 4
	Digest::SHA3::sha3_224_base64 = 5
	Digest::SHA3::sha3_256 = 6
	Digest::SHA3::sha3_256_hex = 7
	Digest::SHA3::sha3_256_base64 = 8
	Digest::SHA3::sha3_384 = 9
	Digest::SHA3::sha3_384_hex = 10
	Digest::SHA3::sha3_384_base64 = 11
	Digest::SHA3::sha3_512 = 12
	Digest::SHA3::sha3_512_hex = 13
	Digest::SHA3::sha3_512_base64 = 14
PREINIT:
	int i;
	unsigned char *data;
	STRLEN len;
	SHA3 *state;
	char *result;
PPCODE:
	if ((state = shaopen(ix2alg[ix])) == NULL)
		XSRETURN_UNDEF;
	for (i = 0; i < items; i++) {
		data = (unsigned char *) (SvPVbyte(ST(i), len));
		while (len > MAX_WRITE_SIZE) {
			shawrite(data, MAX_WRITE_SIZE << 3, state);
			data += MAX_WRITE_SIZE;
			len  -= MAX_WRITE_SIZE;
		}
		shawrite(data, len << 3, state);
	}
	shafinish(state);
	len = 0;
	if (ix % 3 == 0) {
		result = (char *) shadigest(state);
		len = shadsize(state);
	}
	else if (ix % 3 == 1)
		result = shahex(state);
	else
		result = shabase64(state);
	ST(0) = sv_2mortal(newSVpv(result, len));
	shaclose(state);
	XSRETURN(1);

void
hashsize(self)
	SV *	self
ALIAS:
	Digest::SHA3::hashsize = 0
	Digest::SHA3::algorithm = 1
PREINIT:
	SHA3 *state;
	int result;
PPCODE:
	state = INT2PTR(SHA3 *, SvIV(SvRV(SvRV(self))));
	result = ix ? shaalg(state) : shadsize(state) << 3;
	ST(0) = sv_2mortal(newSViv(result));
	XSRETURN(1);

void
add(self, ...)
	SV *	self
PREINIT:
	int i;
	unsigned char *data;
	STRLEN len;
	SHA3 *state;
PPCODE:
	state = INT2PTR(SHA3 *, SvIV(SvRV(SvRV(self))));
	for (i = 1; i < items; i++) {
		data = (unsigned char *) (SvPVbyte(ST(i), len));
		while (len > MAX_WRITE_SIZE) {
			shawrite(data, MAX_WRITE_SIZE << 3, state);
			data += MAX_WRITE_SIZE;
			len  -= MAX_WRITE_SIZE;
		}
		shawrite(data, len << 3, state);
	}
	XSRETURN(1);

void
digest(self)
	SV *	self
ALIAS:
	Digest::SHA3::digest = 0
	Digest::SHA3::Hexdigest = 1
	Digest::SHA3::B64digest = 2
PREINIT:
	STRLEN len;
	SHA3 *state;
	char *result;
PPCODE:
	state = INT2PTR(SHA3 *, SvIV(SvRV(SvRV(self))));
	shafinish(state);
	len = 0;
	if (ix == 0) {
		result = (char *) shadigest(state);
		len = shadsize(state);
	}
	else if (ix == 1)
		result = shahex(state);
	else
		result = shabase64(state);
	ST(0) = sv_2mortal(newSVpv(result, len));
	sharewind(state);
	XSRETURN(1);
