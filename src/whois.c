#include "whois.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net.h"
#include "text.h"

#define WHOIS_PORT "43"
#define IANA_WHOIS_SERVER "whois.iana.org"

/* Sends `query` to `server` on the WHOIS port and returns the full,
 * null-terminated response. WHOIS has no length header, so the response
 * is read in a loop until the server closes the connection. Caller owns
 * the returned buffer and must free() it. */
char *whois_query(const char *server, const char *query)
{
    int sockfd = connect_to_host(server, WHOIS_PORT);

    if (sockfd == -1)
    {
        return NULL;
    }

    char request[256];
    snprintf(request, sizeof(request), "%s\r\n", query);

    if (send(sockfd, request, strlen(request), 0) == -1)
    {
        close(sockfd);
        return NULL;
    }

    size_t capacity = 8192;
    size_t total = 0;
    char *buffer = malloc(capacity);

    if (buffer == NULL)
    {
        close(sockfd);
        return NULL;
    }

    ssize_t bytes_received;

    while ((bytes_received = recv(sockfd, buffer + total, capacity - total - 1, 0)) > 0)
    {
        total += (size_t)bytes_received;

        if (total >= capacity - 1)
        {
            capacity *= 2;
            char *new_buffer = realloc(buffer, capacity);

            if (new_buffer == NULL)
            {
                free(buffer);
                close(sockfd);
                return NULL;
            }

            buffer = new_buffer;
        }
    }

    close(sockfd);

    if (bytes_received == -1 && total == 0)
    {
        free(buffer);
        return NULL;
    }

    sanitize_text(buffer, total, 1);
    buffer[total] = '\0';

    return buffer;
}

/* Scans `response` line by line looking for one that starts with `field`
 * (ignoring leading whitespace, since some WHOIS servers indent fields
 * under a domain block) and copies the value after it into `out`. */
static void extract_field(const char *response, const char *field, char *out, size_t out_size)
{
    size_t field_len = strlen(field);
    const char *line = response;

    while (line != NULL && *line != '\0')
    {
        while (*line == ' ' || *line == '\t')
        {
            line++;
        }

        if (strncmp(line, field, field_len) == 0)
        {
            const char *value = line + field_len;

            while (*value == ' ' || *value == '\t')
            {
                value++;
            }

            const char *line_end = strpbrk(value, "\r\n");
            size_t len = line_end != NULL ? (size_t)(line_end - value) : strlen(value);

            if (len >= out_size)
            {
                len = out_size - 1;
            }

            memcpy(out, value, len);
            out[len] = '\0';
            return;
        }

        const char *next_line = strpbrk(line, "\n");
        line = next_line != NULL ? next_line + 1 : NULL;
    }

    snprintf(out, out_size, "not found");
}

void run_whois(const char *domain)
{
    printf("\n=== WHOIS ===\n");

    const char *tld = strrchr(domain, '.');

    if (tld == NULL || *(tld + 1) == '\0')
    {
        printf("WHOIS: unable to determine TLD for %s\n", domain);
        return;
    }

    tld++;

    char *iana_response = whois_query(IANA_WHOIS_SERVER, tld);

    if (iana_response == NULL)
    {
        printf("WHOIS: failed to query IANA for .%s referral\n", tld);
        return;
    }

    char referral_server[256];

    /* gTLDs (.com, .net, ...) use "whois:"; some ccTLDs use "refer:" instead. */
    extract_field(iana_response, "whois:", referral_server, sizeof(referral_server));

    if (strcmp(referral_server, "not found") == 0)
    {
        extract_field(iana_response, "refer:", referral_server, sizeof(referral_server));
    }

    free(iana_response);

    /* Some registries (e.g. .google) publish an empty "whois:" field. */
    if (strcmp(referral_server, "not found") == 0 || referral_server[0] == '\0')
    {
        printf("WHOIS: no WHOIS server published for .%s\n", tld);
        return;
    }

    printf("WHOIS server: %s\n", referral_server);

    char *domain_response = whois_query(referral_server, domain);

    if (domain_response == NULL)
    {
        printf("WHOIS: failed to query %s for %s\n", referral_server, domain);
        return;
    }

    char registrar[256];
    char creation_date[128];
    char expiry_date[128];
    char name_server[256];

    extract_field(domain_response, "Registrar:", registrar, sizeof(registrar));
    extract_field(domain_response, "Creation Date:", creation_date, sizeof(creation_date));
    extract_field(domain_response, "Registry Expiry Date:", expiry_date, sizeof(expiry_date));
    extract_field(domain_response, "Name Server:", name_server, sizeof(name_server));

    printf("Registrar: %s\n", registrar);
    printf("Creation date: %s\n", creation_date);
    printf("Expiry date: %s\n", expiry_date);
    printf("Name server: %s\n", name_server);

    printf("\nRaw WHOIS response:\n%s\n", domain_response);

    free(domain_response);
}
