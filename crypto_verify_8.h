#ifndef crypto_verify_8_H
#define crypto_verify_8_H

#define crypto_verify_8_tinynacl_BYTES 8
extern int crypto_verify_8_tinynacl(const unsigned char *, const unsigned char *);

#define crypto_verify_8 crypto_verify_8_tinynacl
#define crypto_verify_8_BYTES crypto_verify_8_tinynacl_BYTES
#define crypto_verify_8_IMPLEMENTATION "tinynacl"
#define crypto_verify_8_VERSION "-"

#endif
