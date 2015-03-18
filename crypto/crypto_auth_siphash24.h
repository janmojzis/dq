#ifndef crypto_auth_siphash24_H
#define crypto_auth_siphash24_H

#define crypto_auth_siphash24_tinynacl_BYTES 8
#define crypto_auth_siphash24_tinynacl_KEYBYTES 16
extern int crypto_auth_siphash24_tinynacl(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_auth_siphash24_tinynacl_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);

#define crypto_auth_siphash24 crypto_auth_siphash24_tinynacl
#define crypto_auth_siphash24_verify crypto_auth_siphash24_tinynacl_verify
#define crypto_auth_siphash24_BYTES crypto_auth_siphash24_tinynacl_BYTES
#define crypto_auth_siphash24_KEYBYTES crypto_auth_siphash24_tinynacl_KEYBYTES
#define crypto_auth_siphash24_IMPLEMENTATION "tinynacl"
#define crypto_auth_siphash24_VERSION "-"

#endif
