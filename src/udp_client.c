#include "udp_client.h"
#include <arpa/inet.h>
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

void udp_client_close(udp_client_t *client) {
    if (client == NULL || client->socket_fd < 0) {
        return;
    }

    close(client->socket_fd);
    client->socket_fd = -1;
}
