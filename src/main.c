#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "asn.h"
#include "dns.h"
#include "http.h"
#include "whois.h"

static int format_ip(const struct addrinfo *address, char *out, socklen_t out_size)
{
    const void *addr;

    if (address->ai_family == AF_INET)
    {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address->ai_addr;
        addr = &(ipv4->sin_addr);
    }
    else if (address->ai_family == AF_INET6)
    {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address->ai_addr;
        addr = &(ipv6->sin6_addr);
    }
    else
    {
        return -1;
    }

    return inet_ntop(address->ai_family, addr, out, out_size) != NULL ? 0 : -1;
}

static void print_usage(const char *program)
{
    printf("Usage: %s [--resolver <ipv4>] <domain>\n", program);
    printf("\n");
    printf("  --resolver <ipv4>  Send the DNS record queries (NS, MX, TXT, SOA, CAA) to this\n");
    printf("                     resolver instead of the system ones. Off by default: the\n");
    printf("                     chosen resolver gets to see which domain is being investigated.\n");
}

int main(int argc, char *argv[])
{
    const char *target = NULL;
    const char *resolver_arg = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--resolver") == 0 && i + 1 < argc)
        {
            i++;
            resolver_arg = argv[i];
        }
        else if (target == NULL && argv[i][0] != '-')
        {
            target = argv[i];
        }
        else
        {
            target = NULL;
            break;
        }
    }

    if (target == NULL)
    {
        print_usage(argv[0]);
        return 1;
    }

    struct in_addr resolver_addr;
    const struct in_addr *custom_resolver = NULL;

    if (resolver_arg != NULL)
    {
        if (inet_pton(AF_INET, resolver_arg, &resolver_addr) != 1)
        {
            fprintf(stderr, "Invalid resolver address (IPv4 expected): %s\n", resolver_arg);
            return 1;
        }

        custom_resolver = &resolver_addr;
    }

    const char *port = "80";

    printf("Target: %s\n", target);
    printf("Port: %s/tcp\n", port);

    struct addrinfo hints;
    struct addrinfo *results = NULL;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(target, port, &hints, &results);

    if (status != 0)
    {
        fprintf(stderr, "DNS resolution failed: %s\n", gai_strerror(status));
        run_dns_records(target, custom_resolver);
        run_whois(target);
        return 1;
    }

    printf("Resolved IPs:\n");

    for (struct addrinfo *p = results; p != NULL; p = p->ai_next)
    {
        char ip_address[INET6_ADDRSTRLEN];

        if (format_ip(p, ip_address, sizeof(ip_address)) != 0)
        {
            continue;
        }

        printf("- %s\n", ip_address);

        char hostname[NI_MAXHOST];

        if (getnameinfo(p->ai_addr, p->ai_addrlen, hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD) == 0)
        {
            printf("  PTR: %s\n", hostname);
        }
        else
        {
            printf("  PTR: none\n");
        }

        run_ip_asn_lookup(ip_address);
    }

    int connected = 0;

    for (struct addrinfo *p = results; p != NULL && !connected; p = p->ai_next)
    {
        char ip_address[INET6_ADDRSTRLEN];

        if (format_ip(p, ip_address, sizeof(ip_address)) != 0)
        {
            continue;
        }

        connected = probe_http(p, ip_address, target, port);
    }

    if (!connected)
    {
        printf("TCP connection: failed or unreachable on port %s\n", port);
    }

    freeaddrinfo(results);

    run_dns_records(target, custom_resolver);
    run_whois(target);

    return connected ? 0 : 1;
}
