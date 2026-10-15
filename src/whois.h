#ifndef EXPOSUREPROOF_WHOIS_H
#define EXPOSUREPROOF_WHOIS_H

/* Returns the full NUL-terminated response, which the caller must free(), or NULL. */
char *whois_query(const char *server, const char *query);

void run_whois(const char *domain);

#endif
