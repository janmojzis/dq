#ifndef PRINTRECORD_H
#define PRINTRECORD_H

#include "stralloc.h"

extern long long printrecord_cat(stralloc *out,const unsigned char *buf,long long  len,long long pos,const unsigned char *q,const unsigned char qtype[2]);
extern long long printrecord(stralloc *out,const unsigned char *buf,long long len,long long pos,const unsigned char *q,const unsigned char qtype[2]);

#endif
