#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define SOCKET_TIMEOUT_SECONDS 5

#define WHOIS_PORT "43"
#define IANA_WHOIS_SERVER "whois.iana.org"
#define CYMRU_WHOIS_SERVER "whois.cymru.com"

/* Not every resolver header defines ns_t_caa. */
#define DNS_TYPE_CAA 257

static void set_socket_timeout(int sockfd)
{
    struct timeval timeout = {.tv_sec = SOCKET_TIMEOUT_SECONDS, .tv_usec = 0};

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

/* Everything printed here comes from servers the investigated party may
 * control, so control bytes (terminal escape sequences, embedded NULs) are
 * replaced before they reach the analyst's terminal. */
static void sanitize_text(char *text, size_t length, int keep_newlines)
{
    for (size_t i = 0; i < length; i++)
    {
        unsigned char byte = (unsigned char)text[i];

        if (keep_newlines &&
            (byte == '\n' || byte == '\t' || (byte == '\r' && i + 1 < length && text[i + 1] == '\n')))
        {
            continue;
        }

        if (byte < 0x20 || byte == 0x7f)
        {
            text[i] = '?';
        }
    }
}

/* A plain connect() to a host that silently drops packets blocks for over a
 * minute, so connect in non-blocking mode and wait with poll() instead. */
static int connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int flags = fcntl(sockfd, F_GETFL, 0);

    if (flags == -1 || fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        return -1;
    }

    int result = connect(sockfd, addr, addrlen);

    if (result == -1 && errno == EINPROGRESS)
    {
        struct pollfd pfd = {.fd = sockfd, .events = POLLOUT};
        int error = 0;
        socklen_t error_len = sizeof(error);

        if (poll(&pfd, 1, SOCKET_TIMEOUT_SECONDS * 1000) == 1 &&
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0 &&
            error == 0)
        {
            result = 0;
        }
    }

    if (fcntl(sockfd, F_SETFL, flags) == -1)
    {
        return -1;
    }

    return result;
}

static int connect_to_host(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &results) != 0)
    {
        return -1;
    }

    int sockfd = -1;

    for (struct addrinfo *p = results; p != NULL; p = p->ai_next)
    {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (sockfd == -1)
        {
            continue;
        }

        set_socket_timeout(sockfd);

        if (connect_with_timeout(sockfd, p->ai_addr, p->ai_addrlen) == 0)
        {
            break;
        }

        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(results);

    return sockfd;
}

/* Sends `query` to `server` on the WHOIS port and returns the full,
 * null-terminated response. WHOIS has no length header, so the response
 * is read in a loop until the server closes the connection. Caller owns
 * the returned buffer and must free() it. */
static char *whois_query(const char *server, const char *query)
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

static int recv_exact(int sockfd, unsigned char *buffer, size_t length)
{
    size_t total = 0;

    while (total < length)
    {
        ssize_t bytes_received = recv(sockfd, buffer + total, length - total, 0);

        if (bytes_received <= 0)
        {
            return -1;
        }

        total += (size_t)bytes_received;
    }

    return 0;
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
static void run_dns_records(const char *domain, const struct in_addr *custom_resolver)
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
static void run_ip_asn_lookup(const char *ip_address)
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

static void run_whois(const char *domain)
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

/* Looks `name` up among the response headers. Header names are
 * case-insensitive and the space after the colon is optional. */
static int extract_http_header(const char *response, const char *name, char *out, size_t out_size)
{
    size_t name_len = strlen(name);
    const char *line = strstr(response, "\r\n");

    while (line != NULL)
    {
        line += 2;

        if (*line == '\0' || strncmp(line, "\r\n", 2) == 0)
        {
            break;
        }

        if (strncasecmp(line, name, name_len) == 0 && line[name_len] == ':')
        {
            const char *value = line + name_len + 1;

            while (*value == ' ' || *value == '\t')
            {
                value++;
            }

            size_t len = strcspn(value, "\r\n");

            if (len >= out_size)
            {
                len = out_size - 1;
            }

            memcpy(out, value, len);
            out[len] = '\0';
            return 1;
        }

        line = strstr(line, "\r\n");
    }

    return 0;
}

/* TCP is a stream, so the headers can arrive split across several reads:
 * keep reading until the blank line that ends them, the buffer fills up or
 * the server closes. Returns the number of bytes read or -1. */
static ssize_t recv_http_headers(int sockfd, char *buffer, size_t size)
{
    size_t total = 0;

    buffer[0] = '\0';

    while (total < size - 1)
    {
        ssize_t bytes_received = recv(sockfd, buffer + total, size - 1 - total, 0);

        if (bytes_received == -1 && total == 0)
        {
            return -1;
        }

        if (bytes_received <= 0)
        {
            break;
        }

        total += (size_t)bytes_received;
        buffer[total] = '\0';

        if (strstr(buffer, "\r\n\r\n") != NULL)
        {
            break;
        }
    }

    return (ssize_t)total;
}

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

/* Returns 1 when the HTTP exchange with this address completed, 0 otherwise. */
static int probe_http(const struct addrinfo *address, const char *ip_address, const char *target, const char *port)
{
    int sockfd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);

    if (sockfd == -1)
    {
        return 0;
    }

    set_socket_timeout(sockfd);

    if (connect_with_timeout(sockfd, address->ai_addr, address->ai_addrlen) != 0)
    {
        close(sockfd);
        return 0;
    }

    printf("TCP connection: successful to %s:%s\n", ip_address, port);

    char request[512];

    snprintf(
        request,
        sizeof(request),
        "HEAD / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: ExposureProof-C/0.1\r\n"
        "Connection: close\r\n"
        "\r\n",
        target);

    if (send(sockfd, request, strlen(request), 0) == -1)
    {
        perror("send failed");
        close(sockfd);
        return 0;
    }

    char response[16384];

    ssize_t bytes_received = recv_http_headers(sockfd, response, sizeof(response));

    if (bytes_received == -1)
    {
        perror("recv failed");
        close(sockfd);
        return 0;
    }

    close(sockfd);

    sanitize_text(response, (size_t)bytes_received, 1);

    char *line_end = strstr(response, "\r\n");

    if (line_end != NULL)
    {
        size_t status_line_len = line_end - response;
        char status_line[256];

        if (status_line_len >= sizeof(status_line))
        {
            status_line_len = sizeof(status_line) - 1;
        }

        memcpy(status_line, response, status_line_len);
        status_line[status_line_len] = '\0';

        printf("\nHTTP status: %s\n", status_line);
    }
    else
    {
        printf("\nHTTP status: unavailable\n");
    }

    char location[512];

    if (extract_http_header(response, "Location", location, sizeof(location)))
    {
        printf("HTTP location: %s\n", location);
    }
    else
    {
        printf("HTTP location: not present\n");
    }

    char server[256];

    if (extract_http_header(response, "Server", server, sizeof(server)))
    {
        printf("HTTP server: %s\n", server);
    }
    else
    {
        printf("HTTP server: not disclosed\n");
    }

    printf("\nRaw HTTP response:\n%s\n", response);

    return 1;
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
