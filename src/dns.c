#include "dns.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net.h"
#include "text.h"

/* Not every resolver header defines ns_t_caa. */
#define DNS_TYPE_CAA 257

static void print_mx_record(ns_msg handle, ns_rr rr)
{
    const unsigned char *rdata = ns_rr_rdata(rr);
    char exchange[NS_MAXDNAME];

    if (ns_rr_rdlen(rr) < 3 ||
        dn_expand(ns_msg_base(handle), ns_msg_end(handle), rdata + 2, exchange, sizeof(exchange)) < 0)
    {
        printf("MX: malformed record\n");
        return;
    }

    printf("MX: %s (priority %u)\n", exchange, ns_get16(rdata));
}

static void print_ns_record(ns_msg handle, ns_rr rr)
{
    char name[NS_MAXDNAME];

    if (dn_expand(ns_msg_base(handle), ns_msg_end(handle), ns_rr_rdata(rr), name, sizeof(name)) < 0)
    {
        printf("NS: malformed record\n");
        return;
    }

    printf("NS: %s\n", name);
}

/* TXT rdata is one or more length-prefixed strings, which are meant to be
 * read concatenated (long SPF/DKIM values are split this way). */
static void print_txt_record(ns_rr rr)
{
    const unsigned char *rdata = ns_rr_rdata(rr);
    size_t rdlen = ns_rr_rdlen(rr);
    char text[1024];
    size_t text_len = 0;
    size_t offset = 0;

    while (offset < rdlen)
    {
        size_t segment_len = rdata[offset];
        offset++;

        if (offset + segment_len > rdlen)
        {
            segment_len = rdlen - offset;
        }

        size_t copy_len = segment_len;

        if (text_len + copy_len > sizeof(text) - 1)
        {
            copy_len = sizeof(text) - 1 - text_len;
        }

        memcpy(text + text_len, rdata + offset, copy_len);
        text_len += copy_len;
        offset += segment_len;
    }

    sanitize_text(text, text_len, 0);
    text[text_len] = '\0';

    printf("TXT: %s\n", text);
}

static void print_soa_record(ns_msg handle, ns_rr rr)
{
    const unsigned char *rdata = ns_rr_rdata(rr);
    const unsigned char *rdata_end = rdata + ns_rr_rdlen(rr);
    char primary[NS_MAXDNAME];
    char admin[NS_MAXDNAME];

    int consumed = dn_expand(ns_msg_base(handle), ns_msg_end(handle), rdata, primary, sizeof(primary));

    if (consumed < 0)
    {
        printf("SOA: malformed record\n");
        return;
    }

    rdata += consumed;
    consumed = dn_expand(ns_msg_base(handle), ns_msg_end(handle), rdata, admin, sizeof(admin));

    if (consumed < 0 || rdata + consumed + 4 > rdata_end)
    {
        printf("SOA: malformed record\n");
        return;
    }

    rdata += consumed;

    printf("SOA: primary=%s admin=%s serial=%lu\n", primary, admin, (unsigned long)ns_get32(rdata));
}

static void print_caa_record(ns_rr rr)
{
    const unsigned char *rdata = ns_rr_rdata(rr);
    size_t rdlen = ns_rr_rdlen(rr);

    if (rdlen < 2 || (size_t)rdata[1] + 2 > rdlen)
    {
        printf("CAA: malformed record\n");
        return;
    }

    size_t tag_len = rdata[1];
    size_t value_len = rdlen - 2 - tag_len;
    char tag[256];
    char value[512];

    memcpy(tag, rdata + 2, tag_len);
    sanitize_text(tag, tag_len, 0);
    tag[tag_len] = '\0';

    if (value_len > sizeof(value) - 1)
    {
        value_len = sizeof(value) - 1;
    }

    memcpy(value, rdata + 2 + tag_len, value_len);
    sanitize_text(value, value_len, 0);
    value[value_len] = '\0';

    printf("CAA: %s \"%s\" (flags %u)\n", tag, value, rdata[0]);
}

static int dns_exchange_udp(const struct sockaddr_in *nameserver, const unsigned char *query, int query_len,
                            unsigned char *response, int response_size)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd == -1)
    {
        return -1;
    }

    set_socket_timeout(sockfd);

    ssize_t len = -1;

    /* connect() on a UDP socket makes the kernel drop replies from anyone else. */
    if (connect(sockfd, (const struct sockaddr *)nameserver, sizeof(*nameserver)) == 0 &&
        send(sockfd, query, (size_t)query_len, 0) == query_len)
    {
        len = recv(sockfd, response, (size_t)response_size, 0);
    }

    close(sockfd);

    if (len < NS_HFIXEDSZ || memcmp(query, response, 2) != 0)
    {
        return -1;
    }

    return (int)len;
}

/* DNS over TCP prefixes each message with its length as a 16-bit big-endian integer. */
static int dns_exchange_tcp(const struct sockaddr_in *nameserver, const unsigned char *query, int query_len,
                            unsigned char *response, int response_size)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
    {
        return -1;
    }

    set_socket_timeout(sockfd);

    unsigned char prefix[2] = {(unsigned char)(query_len >> 8), (unsigned char)(query_len & 0xff)};
    int len = -1;

    if (connect_with_timeout(sockfd, (const struct sockaddr *)nameserver, sizeof(*nameserver)) == 0 &&
        send(sockfd, prefix, sizeof(prefix), 0) == (ssize_t)sizeof(prefix) &&
        send(sockfd, query, (size_t)query_len, 0) == query_len &&
        recv_exact(sockfd, prefix, sizeof(prefix)) == 0)
    {
        int message_len = (prefix[0] << 8) | prefix[1];

        if (message_len >= NS_HFIXEDSZ && message_len <= response_size &&
            recv_exact(sockfd, response, (size_t)message_len) == 0)
        {
            len = message_len;
        }
    }

    close(sockfd);

    return len;
}

/* Asks each system nameserver in turn, over UDP first and over TCP when the
 * answer is truncated. Done with our own sockets because libresolv's TCP
 * fallback has no read timeout and hangs on nameservers that accept the
 * connection but never answer. Returns the response length or -1. */
static int dns_query(res_state resolver, const char *domain, int type, unsigned char *response, int response_size)
{
    unsigned char query[NS_PACKETSZ];
    int query_len = res_nmkquery(resolver, ns_o_query, domain, ns_c_in, type, NULL, 0, NULL, query, sizeof(query));

    if (query_len < 0)
    {
        return -1;
    }

    for (int i = 0; i < resolver->nscount; i++)
    {
        const struct sockaddr_in *nameserver = &resolver->nsaddr_list[i];

        if (nameserver->sin_family != AF_INET)
        {
            continue;
        }

        int len = dns_exchange_udp(nameserver, query, query_len, response, response_size);

        if (len >= 0 && (response[2] & 0x02) != 0)
        {
            len = dns_exchange_tcp(nameserver, query, query_len, response, response_size);
        }

        /* SERVFAIL, REFUSED and the like say nothing about the domain, so
         * they count as a failed lookup rather than as "no records". */
        if (len >= 0)
        {
            int rcode = response[3] & 0x0f;

            if (rcode == ns_r_noerror || rcode == ns_r_nxdomain)
            {
                return len;
            }
        }
    }

    return -1;
}

static void query_dns_records(res_state resolver, const char *domain, int type, const char *label)
{
    static unsigned char response[NS_MAXMSG];
    int len = dns_query(resolver, domain, type, response, sizeof(response));

    if (len < 0)
    {
        printf("%s: lookup failed\n", label);
        return;
    }

    ns_msg handle;

    if (ns_initparse(response, len, &handle) < 0)
    {
        printf("%s: failed to parse response\n", label);
        return;
    }

    int count = ns_msg_count(handle, ns_s_an);
    int printed = 0;

    for (int i = 0; i < count; i++)
    {
        ns_rr rr;

        if (ns_parserr(&handle, ns_s_an, i, &rr) != 0 || (int)ns_rr_type(rr) != type)
        {
            continue;
        }

        printed++;

        switch (type)
        {
        case ns_t_mx:
            print_mx_record(handle, rr);
            break;
        case ns_t_ns:
            print_ns_record(handle, rr);
            break;
        case ns_t_txt:
            print_txt_record(rr);
            break;
        case ns_t_soa:
            print_soa_record(handle, rr);
            break;
        case DNS_TYPE_CAA:
            print_caa_record(rr);
            break;
        default:
            break;
        }
    }

    if (printed == 0)
    {
        printf("%s: none\n", label);
    }
}

/* `custom_resolver` is NULL to use the system nameservers. */
void run_dns_records(const char *domain, const struct in_addr *custom_resolver)
{
    printf("\n=== DNS records ===\n");

    /* Only used for the system nameserver list and to build query packets. */
    struct __res_state resolver;

    memset(&resolver, 0, sizeof(resolver));

    if (res_ninit(&resolver) != 0)
    {
        printf("DNS records: failed to initialize resolver\n");
        return;
    }

    if (custom_resolver != NULL)
    {
        char resolver_ip[INET_ADDRSTRLEN];

        memset(&resolver.nsaddr_list[0], 0, sizeof(resolver.nsaddr_list[0]));
        resolver.nsaddr_list[0].sin_family = AF_INET;
        resolver.nsaddr_list[0].sin_port = htons(NS_DEFAULTPORT);
        resolver.nsaddr_list[0].sin_addr = *custom_resolver;
        resolver.nscount = 1;

        inet_ntop(AF_INET, custom_resolver, resolver_ip, sizeof(resolver_ip));
        printf("Resolver: %s (custom)\n", resolver_ip);
    }
    else
    {
        printf("Resolver: system\n");
    }

    query_dns_records(&resolver, domain, ns_t_ns, "NS");
    query_dns_records(&resolver, domain, ns_t_mx, "MX");
    query_dns_records(&resolver, domain, ns_t_txt, "TXT");
    query_dns_records(&resolver, domain, ns_t_soa, "SOA");
    query_dns_records(&resolver, domain, DNS_TYPE_CAA, "CAA");

    res_nclose(&resolver);
}
