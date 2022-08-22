/*
 * 20131204
 * Jan Mojzis
 * Public domain.
 */

#include "hexdecode.h"
#include "base32decode.h"
#include "byte.h"
#include "str.h"
#include "keyparse.h"

int keyparse(unsigned char *keys, long long keyslen, const char *xx) {

    long long len;
    const unsigned char *x = (const unsigned char *)xx;

    if (!xx) return 0;
    if (keyslen != 32) return 0;

    len = str_len(xx);

    switch (len) {
        case 54:
            if (!byte_isequal(x, 3, "uz5")) return 0;
            if (!base32decode(keys, 32, x + 3, 51)) return 0;
            break;
        case 51:
            if (!base32decode(keys, 32, x, 51)) return 0;
            break;
        case 64:
            if (!hexdecode(keys, 32, x, 64)) return 0;
            break;
        default:
            return 0;
    }
    return 1;
}
