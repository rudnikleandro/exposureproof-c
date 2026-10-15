#ifndef EXPOSUREPROOF_HTTP_H
#define EXPOSUREPROOF_HTTP_H

#include <netdb.h>

/* Returns 1 when the HTTP exchange with this address completed, 0 otherwise. */
int probe_http(const struct addrinfo *address, const char *ip_address, const char *target,
               const char *port);

#endif
