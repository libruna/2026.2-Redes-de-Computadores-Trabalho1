#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include "dns_protocol.h"
#include <stddef.h>
#include <stdint.h>

#define DNS_MAX_MX_RECORDS 16

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
} dns_header_t;

typedef struct {
    char name[DNS_MAX_NAME_SIZE];
    uint16_t type;
    uint16_t rr_class;
    uint32_t ttl;
    uint16_t rdata_length;
    size_t rdata_offset;
} dns_record_t;

typedef struct {
    uint16_t preference;
    char exchange[DNS_MAX_NAME_SIZE];
} dns_mx_record_t;

typedef struct {
    size_t count;
    dns_mx_record_t records[DNS_MAX_MX_RECORDS];
} dns_mx_list_t;

dns_status_t dns_parser_read_header(const uint8_t *response, size_t response_size, uint16_t expected_id, dns_header_t *header);

// indica onde comeca o campo seguinte ao nome
dns_status_t dns_parser_read_name(const uint8_t *message, size_t message_size, size_t offset, char *name, size_t name_size,
                                  size_t *next_offset);

dns_status_t dns_parser_skip_question(const uint8_t *message, size_t message_size, size_t offset, size_t *next_offset);

// guarda a posicao e o tamanho do RDATA sem interpreta-lo
dns_status_t dns_parser_read_record(const uint8_t *message, size_t message_size, size_t offset, dns_record_t *record,
                                    size_t *next_offset);

// guarda os registros MX na ordem do pacote ate o limite definido
dns_status_t dns_parser_parse_mx(const uint8_t *response, size_t response_size, uint16_t expected_id, dns_mx_list_t *result);

#endif
