/*
20130505
Jan Mojzis
Public domain.
*/

#include <time.h>
#include <sys/time.h>
#include "milliseconds.h"

long long milliseconds(void) {

    struct timeval t;
    gettimeofday(&t, (struct timezone *)0);
    return t.tv_sec * 1000LL + t.tv_usec / 1000LL;

}

