#ifndef EXPOSUREPROOF_DNS_H
#define EXPOSUREPROOF_DNS_H

#include <netinet/in.h>

/* `custom_resolver` is NULL to use the system nameservers. */
void run_dns_records(const char *domain, const struct in_addr *custom_resolver);

#endif
