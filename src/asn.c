#include "asn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "whois.h"

#define CYMRU_WHOIS_SERVER "whois.cymru.com"

static void trim_spaces(char *str)
{
    char *start = str;

    while (*start == ' ')
    {
        start++;
    }

    memmove(str, start, strlen(start) + 1);

    size_t len = strlen(str);

    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\r'))
    {
        len--;
        str[len] = '\0';
    }
}

/* Team Cymru answers " -v <ip>" with a header line followed by one line of
 * "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name". */
void run_ip_asn_lookup(const char *ip_address)
{
    char query[128];
    snprintf(query, sizeof(query), " -v %s", ip_address);

    char *response = whois_query(CYMRU_WHOIS_SERVER, query);

    if (response == NULL)
    {
        printf("  ASN: lookup failed\n");
        return;
    }

    char *data_line = strchr(response, '\n');
    char *fields[7];
    int field_count = 0;

    if (data_line != NULL)
    {
        data_line++;

        char *line_end = strchr(data_line, '\n');

        if (line_end != NULL)
        {
            *line_end = '\0';
        }

        char *saveptr;

        for (char *token = strtok_r(data_line, "|", &saveptr);
             token != NULL && field_count < 7;
             token = strtok_r(NULL, "|", &saveptr))
        {
            trim_spaces(token);
            fields[field_count] = token;
            field_count++;
        }
    }

    if (field_count < 7)
    {
        printf("  ASN: not found\n");
    }
    else if (strcmp(fields[0], "NA") == 0)
    {
        printf("  ASN: none (private or unannounced address)\n");
    }
    else
    {
        printf("  ASN: AS%s (%s)\n", fields[0], fields[6]);
        printf("  BGP prefix: %s\n", fields[2]);
        printf("  Country: %s | Registry: %s | Allocated: %s\n", fields[3], fields[4], fields[5]);
    }

    free(response);
}
