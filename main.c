#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(int argc, char *argv[]) {
    if (argc !=2) {
        printf("Usage: %s <domain>\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];

    printf("Target: %s\n", target);

    struct addrinfo hints;
    struct addrinfo *results = NULL;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(target, NULL, &hints, &results);

    if (status != 0) {
        fprintf(stderr, "DNS resolution failed: %s\n", gai_strerror(status));
        return 1;
    }

    printf("Resolved IPs:\n");

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
    }

    freeaddrinfo(results);

    return 0;   
}