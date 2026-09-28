#include "udp_client.h"
#include <arpa/inet.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

udp_client_status_t udp_client_open(udp_client_t *client, const char *server_ip) {

    if (client == NULL || server_ip == NULL) {
        return UDP_CLIENT_INVALID_ARGUMENT;
    }

    // indica que nenhum socket foi criado ainda
    client->socket_fd = -1;
    memset(&client->server_address, 0, sizeof(client->server_address));

    // configura o destino como um servidor DNS 
    client->server_address.sin_family = AF_INET;
    client->server_address.sin_port = htons(UDP_CLIENT_DNS_PORT);

    // converte o endereco recebido em texto para binario
    if (inet_pton(AF_INET, server_ip, &client->server_address.sin_addr) != 1) {
    	return UDP_CLIENT_INVALID_IP;
    }

    client->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (client->socket_fd < 0) {
        return UDP_CLIENT_SOCKET_ERROR;
    }

    return UDP_CLIENT_OK;
}

udp_client_status_t udp_client_send(const udp_client_t *client, const uint8_t *request, size_t request_size) {

    if (client == NULL || client->socket_fd < 0 ||
        request == NULL || request_size == 0) {
        return UDP_CLIENT_INVALID_ARGUMENT;
    }

    // envia os bytes como um datagrama UDP e registra quantos foram aceitos para envio
    ssize_t sent_bytes = sendto(
        client->socket_fd,
        request,
        request_size,
        0,
        (const struct sockaddr *)&client->server_address,
        sizeof(client->server_address)
    );

    if (sent_bytes < 0 || (size_t)sent_bytes != request_size) {
        return UDP_CLIENT_SEND_ERROR;
    }

    return UDP_CLIENT_OK;
}

udp_client_status_t udp_client_receive(const udp_client_t *client, uint8_t *response, size_t response_capacity, size_t *response_size) {

    if (client == NULL || client->socket_fd < 0 || response == NULL ||
        response_capacity == 0 || response_size == NULL) {
        return UDP_CLIENT_INVALID_ARGUMENT;
    }
    
    *response_size = 0;

    struct pollfd socket_event = {
        .fd = client->socket_fd,
        .events = POLLIN,
        .revents = 0
    };

    // aguarda por no maximo dois segundos
    int poll_result = poll(&socket_event, 1, UDP_CLIENT_TIMEOUT_MS);
    if (poll_result == 0) {
        return UDP_CLIENT_TIMEOUT;
    }

    if (poll_result < 0 || (socket_event.revents & POLLIN) == 0) {
        return UDP_CLIENT_RECEIVE_ERROR;
    }

    struct sockaddr_in source_address = {0};
    socklen_t source_address_size = sizeof(source_address);
    ssize_t received_bytes = recvfrom(
        client->socket_fd,
        response,
        response_capacity,
        0,
        (struct sockaddr *)&source_address,
        &source_address_size
    );

    if (received_bytes < 0) {
        return UDP_CLIENT_RECEIVE_ERROR;
    }

    if (source_address.sin_family != client->server_address.sin_family ||
        source_address.sin_addr.s_addr != client->server_address.sin_addr.s_addr ||
        source_address.sin_port != client->server_address.sin_port) {
        return UDP_CLIENT_UNEXPECTED_SOURCE;
    }

    *response_size = (size_t)received_bytes;
    
    return UDP_CLIENT_OK;
}

void udp_client_close(udp_client_t *client) {
    if (client == NULL || client->socket_fd < 0) {
        return;
    }

    close(client->socket_fd);
    client->socket_fd = -1;
}
