#ifndef crypto_stream_salsa20_H
#define crypto_stream_salsa20_H

#define crypto_stream_salsa20_tinynacl_KEYBYTES 32
#define crypto_stream_salsa20_tinynacl_NONCEBYTES 8
extern int crypto_stream_salsa20_tinynacl(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_stream_salsa20_tinynacl_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);

#define crypto_stream_salsa20 crypto_stream_salsa20_tinynacl
#define crypto_stream_salsa20_xor crypto_stream_salsa20_tinynacl_xor
#define crypto_stream_salsa20_KEYBYTES crypto_stream_salsa20_tinynacl_KEYBYTES
#define crypto_stream_salsa20_NONCEBYTES crypto_stream_salsa20_tinynacl_NONCEBYTES
#define crypto_stream_salsa20_IMPLEMENTATION "tinynacl"
#define crypto_stream_salsa20_VERSION "-"

#endif
