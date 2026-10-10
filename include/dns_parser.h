#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define DNS_HEADER_SIZE 12
#define DNS_MAX_MESSAGE_SIZE 512
#define DNS_MAX_NAME_SIZE 256
#define DNS_MAX_MX_RECORDS 16

// TODO(#16): move to the shared header once it is merged
typedef enum {
    DNS_OK = 0,
    DNS_INVALID_ARGUMENT,
    DNS_NXDOMAIN,
    DNS_NO_MX,
    DNS_INVALID_RESPONSE,
    DNS_SERVER_ERROR
} dns_status_t;

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
} dns_header_t;

typedef struct {
    uint16_t preference;
    char exchange[DNS_MAX_NAME_SIZE];
} dns_mx_record_t;

typedef struct {
    size_t count;
    dns_mx_record_t records[DNS_MAX_MX_RECORDS];
} dns_mx_list_t;

dns_status_t dns_parser_read_header(const uint8_t *response, size_t response_size, uint16_t expected_id, dns_header_t *header);

#endif
