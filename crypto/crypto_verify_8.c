#include "verify.h"
#include "crypto_verify_8.h"

int crypto_verify_8_tinynacl(const unsigned char *x, const unsigned char *y) {
    return verify(x, y, 8);
}
