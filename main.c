#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc !=2) {
        printf("Usage: %s <domain>\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];
    const char *port = "80";

    printf("Target: %s\n", target);
    printf("Port: %s/tcp\n", port);

    struct addrinfo hints;
    struct addrinfo *results = NULL;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(target, port, &hints, &results);

    if (status != 0) {
        fprintf(stderr, "DNS resolution failed: %s\n", gai_strerror(status));
        return 1;
    }

    printf("Resolved IPs:\n");

    int connected = 0;

    for (struct addrinfo *p = results; p != NULL; p = p->ai_next) {
        char ip_address[INET6_ADDRSTRLEN];
        void *addr;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else if (p->ai_family ==AF_INET6) {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        } else {
            continue;
        }

        inet_ntop(p->ai_family, addr, ip_address, sizeof(ip_address));
        printf("- %s\n", ip_address);

        int sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (sockfd == -1) {
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) {
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
                target
            );

            ssize_t bytes_sent = send(sockfd, request, strlen(request), 0);

            if (bytes_sent == 1) {
                perror("send failed");
                close(sockfd);
                continue;
            }

            char response[4096];

            ssize_t bytes_received = recv(sockfd, response, sizeof(response) -1, 0);

            if (bytes_received == -1) {
                perror("recv failed");
                close(sockfd);
                continue;
            }

            response[bytes_received] = '\0';

            char *line_end = strstr(response, "\r\n");

            if (line_end != NULL) {
                size_t status_line_len = line_end - response;
                char status_line[256];
                
                if (status_line_len >= sizeof(status_line)) {
                    status_line_len = sizeof(status_line) -1;
                }

                memcpy(status_line, response, status_line_len);
                status_line[status_line_len] = '\0';

                printf("\nHTTP status: %s\n", status_line);
            } else {
                printf("\nHTTP status: unvailable\n");
            }

            printf("\nRaw HTTP response:\n%s\n", response);

            connected = 1;
            close(sockfd);
            break;
        }

        close(sockfd);
    }

    if (!connected) {
        printf("TCP connection: failed or unreachable on port %s\n", port);
    }

    freeaddrinfo(results);

    return connected ? 0 : 1;   
}