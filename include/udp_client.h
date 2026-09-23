#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#define UDP_CLIENT_DNS_PORT 53

typedef enum {
    UDP_CLIENT_OK = 0,
    UDP_CLIENT_INVALID_ARGUMENT,
    UDP_CLIENT_INVALID_IP,
    UDP_CLIENT_SOCKET_ERROR,
    UDP_CLIENT_SEND_ERROR
} udp_client_status_t;

typedef struct {
    int socket_fd;
    struct sockaddr_in server_address;
} udp_client_t;

udp_client_status_t udp_client_open(udp_client_t *client, const char *server_ip);
udp_client_status_t udp_client_send(const udp_client_t *client, const uint8_t *request, size_t request_size);

void udp_client_close(udp_client_t *client);

#endif
