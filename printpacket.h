#ifndef PRINTPACKET_H
#define PRINTPACKET_H

#include "stralloc.h"

extern int printpacket_cat(stralloc *out, unsigned char *buf, long long len);

#endif
