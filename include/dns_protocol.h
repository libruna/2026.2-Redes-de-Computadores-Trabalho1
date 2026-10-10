#ifndef DNS_PROTOCOL_H
#define DNS_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DNS_HEADER_SIZE 12
#define DNS_MAX_MESSAGE_SIZE 512
#define DNS_MAX_NAME_SIZE 256
#define DNS_MAX_DOMAIN_SIZE 253
#define DNS_MAX_LABEL_SIZE 63

#define DNS_QUERY_RECURSION_DESIRED 0x0100
#define DNS_TYPE_MX 15
#define DNS_CLASS_IN 1

typedef enum {
    DNS_OK = 0,
    DNS_INVALID_ARGUMENT,
    DNS_NXDOMAIN,
    DNS_NO_MX,
    DNS_INVALID_RESPONSE,
    DNS_SERVER_ERROR,
    DNS_INVALID_DOMAIN,
    DNS_BUFFER_TOO_SMALL,
    DNS_RANDOM_ERROR
} dns_status_t;

// verifica se o dominio pode ser codificado como QNAME
bool dns_protocol_is_valid_domain(const char *domain);

// gera o identificador que relaciona consulta e resposta
dns_status_t dns_protocol_generate_transaction_id(uint16_t *transaction_id);

// monta a consulta MX no buffer fornecido
dns_status_t dns_protocol_build_mx_query(const char *domain, uint16_t transaction_id, uint8_t *query,
                                         size_t query_capacity, size_t *query_size);

#endif
