#include "dns_protocol.h"
#include <errno.h>
#include <string.h>
#include <sys/random.h>

#define DNS_QUESTION_COUNT 1
#define DNS_QUESTION_FIXED_SIZE 4

static bool is_domain_character(char character) {

    return (character >= 'a' && character <= 'z') ||
           (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9') ||
           character == '-';
}

// valida os rotulos e calcula o tamanho do QNAME
static dns_status_t get_qname_size(const char *domain, size_t *qname_size) {

    if (domain == NULL || qname_size == NULL) {
        return DNS_INVALID_ARGUMENT;
    }

    size_t domain_size = strlen(domain);
    if (domain_size == 0) {
        return DNS_INVALID_DOMAIN;
    }

    size_t name_size = domain_size;
    if (domain[domain_size - 1] == '.') {
        name_size--;
    }

    if (name_size == 0 || name_size > DNS_MAX_DOMAIN_SIZE) {
        return DNS_INVALID_DOMAIN;
    }

    size_t label_size = 0;
    for (size_t index = 0; index < name_size; ++index) {
        char character = domain[index];

        if (character == '.') {
            if (label_size == 0 || domain[index - 1] == '-') {
                return DNS_INVALID_DOMAIN;
            }
            label_size = 0;
            continue;
        }

        if (!is_domain_character(character) ||
            (label_size == 0 && character == '-')) {
            return DNS_INVALID_DOMAIN;
        }

        label_size++;
        if (label_size > DNS_MAX_LABEL_SIZE) {
            return DNS_INVALID_DOMAIN;
        }
    }

    if (label_size == 0 || domain[name_size - 1] == '-') {
        return DNS_INVALID_DOMAIN;
    }

    // os pontos viram tamanhos; sobram o primeiro tamanho e o zero final
    *qname_size = name_size + 2;
    return DNS_OK;
}

static void write_u16(uint8_t *destination, uint16_t value) {

    destination[0] = (uint8_t)(value >> 8);
    destination[1] = (uint8_t)(value & 0xFF);
}

// codifica cada rotulo como tamanho seguido pelos caracteres
static size_t write_qname(uint8_t *destination, const char *domain) {

    size_t output = 0;
    size_t label_start = 0;
    size_t domain_size = strlen(domain);

    if (domain[domain_size - 1] == '.') {
        domain_size--;
    }

    for (size_t index = 0; index <= domain_size; ++index) {
        if (index == domain_size || domain[index] == '.') {
            size_t label_size = index - label_start;
            destination[output++] = (uint8_t)label_size;
            memcpy(destination + output, domain + label_start, label_size);
            output += label_size;
            label_start = index + 1;
        }
    }

    destination[output++] = 0;
    return output;
}

bool dns_protocol_is_valid_domain(const char *domain) {

    size_t qname_size = 0;
    return get_qname_size(domain, &qname_size) == DNS_OK;
}

dns_status_t dns_protocol_generate_transaction_id(uint16_t *transaction_id) {

    if (transaction_id == NULL) {
        return DNS_INVALID_ARGUMENT;
    }

    size_t received = 0;
    uint8_t random_bytes[sizeof(*transaction_id)];

    // continua se o sistema interromper a geracao dos 16 bits
    while (received < sizeof(random_bytes)) {
        ssize_t result = getrandom(random_bytes + received, sizeof(random_bytes) - received, 0);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return DNS_RANDOM_ERROR;
        }
        if (result == 0) {
            return DNS_RANDOM_ERROR;
        }
        received += (size_t)result;
    }

    *transaction_id = (uint16_t)(((uint16_t)random_bytes[0] << 8) | random_bytes[1]);
    return DNS_OK;
}

dns_status_t dns_protocol_build_mx_query(const char *domain, uint16_t transaction_id, uint8_t *query,
                                         size_t query_capacity, size_t *query_size) {

    if (query_size == NULL) {
        return DNS_INVALID_ARGUMENT;
    }
    *query_size = 0;

    if (domain == NULL || query == NULL) {
        return DNS_INVALID_ARGUMENT;
    }

    size_t qname_size = 0;
    dns_status_t status = get_qname_size(domain, &qname_size);
    if (status != DNS_OK) {
        return status;
    }

    size_t required_size = DNS_HEADER_SIZE + qname_size + DNS_QUESTION_FIXED_SIZE;
    if (query_capacity < required_size) {
        return DNS_BUFFER_TOO_SMALL;
    }

    // zera o cabecalho antes de preencher os tres campos usados na consulta
    memset(query, 0, DNS_HEADER_SIZE);
    write_u16(query, transaction_id);
    write_u16(query + 2, DNS_QUERY_RECURSION_DESIRED);
    write_u16(query + 4, DNS_QUESTION_COUNT);

    size_t offset = DNS_HEADER_SIZE;
    offset += write_qname(query + offset, domain);

    // solicita um registro MX da classe Internet
    write_u16(query + offset, DNS_TYPE_MX);
    offset += 2;
    write_u16(query + offset, DNS_CLASS_IN);
    offset += 2;

    *query_size = offset;
    return DNS_OK;
}
