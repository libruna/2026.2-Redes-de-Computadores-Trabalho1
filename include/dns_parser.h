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

// next_offset: where the field after the name starts (after the first pointer, if any)
dns_status_t dns_parser_read_name(const uint8_t *message, size_t message_size, size_t offset, char *name, size_t name_size,
                                  size_t *next_offset);

dns_status_t dns_parser_skip_question(const uint8_t *message, size_t message_size, size_t offset, size_t *next_offset);

// RDATA is not interpreted: record->rdata_offset and rdata_length point to it
dns_status_t dns_parser_read_record(const uint8_t *message, size_t message_size, size_t offset, dns_record_t *record,
                                    size_t *next_offset);

// Keeps up to DNS_MAX_MX_RECORDS in packet order; extra records are ignored
dns_status_t dns_parser_parse_mx(const uint8_t *response, size_t response_size, uint16_t expected_id, dns_mx_list_t *result);

#endif
