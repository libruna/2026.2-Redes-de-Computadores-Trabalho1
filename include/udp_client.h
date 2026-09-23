#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

#include <netinet/in.h>

#define UDP_CLIENT_DNS_PORT 53

typedef enum {
    UDP_CLIENT_OK = 0,
    UDP_CLIENT_INVALID_IP,
    UDP_CLIENT_SOCKET_ERROR
} udp_client_status_t;

typedef struct {
    int socket_fd;
    struct sockaddr_in server_address;
} udp_client_t;

udp_client_status_t udp_client_open(udp_client_t *client, const char *server_ip);

void udp_client_close(udp_client_t *client);

#endif
