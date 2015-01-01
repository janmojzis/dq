/* Public domain. */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main() {

    int s, r;
    struct sockaddr_in6 sa;
    int opt = 1;

    s = socket(PF_INET6, SOCK_DGRAM, 0);
    if (s == -1) return 111;
    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof opt);

    memset(&sa, 0, sizeof sa);
    sa.sin6_family = PF_INET6;
    memcpy(&sa.sin6_addr, "\0\0\0\0\0\0\0\0\0\0\377\377\177\0\0\1", 16);
    memcpy(&sa.sin6_port, "\1\1", 2);
    sa.sin6_scope_id = 0;
    sa.sin6_flowinfo = 0;

    printf("/* Public domain. */\n\n");
    printf("#define HASIPV6 1\n");
    return 0;
}
