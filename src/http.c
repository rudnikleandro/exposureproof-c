#include "http.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net.h"
#include "text.h"

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

/* Returns 1 when the HTTP exchange with this address completed, 0 otherwise. */
int probe_http(const struct addrinfo *address, const char *ip_address, const char *target, const char *port)
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
