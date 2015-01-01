#ifndef _SALSA_H____
#define _SALSA_H____

#include "crypto_uint32.h"

extern int salsa_stream_xor(unsigned char *, const unsigned char *, unsigned long long, const unsigned char *, const unsigned char *, long long);
extern int salsa_hash(unsigned char *, const unsigned char *, const unsigned char *, long long);

#endif
