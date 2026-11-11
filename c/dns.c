/* getaddrinfo/freeaddrinfo/inet_ntop are POSIX.1-2001; request them under
 * a strict -std=c99 build. Must precede any system header. */
#define _POSIX_C_SOURCE 200112L

#include "dns.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

int alosint_dns_lookup(const char *domain, char *ip_out, int max_len)
{
    if (domain == NULL || ip_out == NULL || max_len <= 0) {
        return -1;
    }

    /* Never leave the output uninitialized for callers that ignore the code. */
    ip_out[0] = '\0';

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;     /* IPv4 only */
    hints.ai_socktype = SOCK_STREAM; /* one entry per address, not per proto */

    struct addrinfo *res = NULL;
    if (getaddrinfo(domain, NULL, &hints, &res) != 0 || res == NULL) {
        return -2;
    }

    int status = -3; /* walked the list, found no usable IPv4 address */
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET || ai->ai_addr == NULL) {
            continue;
        }

        /* Cast via void* so -Wcast-align stays quiet; ai_addr is suitably
         * aligned for a sockaddr_in by getaddrinfo's contract. */
        struct sockaddr_in *sin = (struct sockaddr_in *)(void *)ai->ai_addr;

        char text[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &sin->sin_addr, text, sizeof(text)) == NULL) {
            continue;
        }

        size_t needed = strlen(text) + 1; /* include NUL */
        if (needed > (size_t)max_len) {
            status = -4; /* result does not fit in the caller's buffer */
            break;
        }

        memcpy(ip_out, text, needed);
        status = 0;
        break;
    }

    freeaddrinfo(res);
    return status;
}
