#ifndef crypto_core_salsa20_H
#define crypto_core_salsa20_H

#define crypto_core_salsa20_tinynacl_OUTPUTBYTES 64
#define crypto_core_salsa20_tinynacl_INPUTBYTES 16
#define crypto_core_salsa20_tinynacl_KEYBYTES 32
#define crypto_core_salsa20_tinynacl_CONSTBYTES 16
extern int crypto_core_salsa20_tinynacl(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);

#define crypto_core_salsa20 crypto_core_salsa20_tinynacl
#define crypto_core_salsa20_OUTPUTBYTES crypto_core_salsa20_tinynacl_OUTPUTBYTES
#define crypto_core_salsa20_INPUTBYTES crypto_core_salsa20_tinynacl_INPUTBYTES
#define crypto_core_salsa20_KEYBYTES crypto_core_salsa20_tinynacl_KEYBYTES
#define crypto_core_salsa20_CONSTBYTES crypto_core_salsa20_tinynacl_CONSTBYTES
#define crypto_core_salsa20_IMPLEMENTATION "tinynacl"
#define crypto_core_salsa20_VERSION "-"

#endif