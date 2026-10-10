#include "dns_parser.h"
#include <stddef.h>

#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_TC 0x0200
#define DNS_RCODE_MASK 0x000F
#define DNS_RCODE_NO_ERROR 0
#define DNS_RCODE_NXDOMAIN 3

// builds the value byte by byte: casting to uint16_t * could be misaligned
static uint16_t read_u16(const uint8_t *data) {
    return (uint16_t)((data[0] << 8) | data[1]);
}

dns_status_t dns_parser_read_header(const uint8_t *response, size_t response_size, uint16_t expected_id, dns_header_t *header) {

    if (response == NULL || header == NULL) {
        return DNS_INVALID_ARGUMENT;
    }

    if (response_size < DNS_HEADER_SIZE) {
        return DNS_INVALID_RESPONSE;
    }

    header->id = read_u16(response);
    header->flags = read_u16(response + 2);
    header->question_count = read_u16(response + 4);
    header->answer_count = read_u16(response + 6);
    header->authority_count = read_u16(response + 8);
    header->additional_count = read_u16(response + 10);

    if (header->id != expected_id) {
        return DNS_INVALID_RESPONSE;
    }

    if ((header->flags & DNS_FLAG_QR) == 0) {
        return DNS_INVALID_RESPONSE;
    }

    if ((header->flags & DNS_FLAG_TC) != 0) {
        return DNS_INVALID_RESPONSE;
    }

    switch (header->flags & DNS_RCODE_MASK) {
    case DNS_RCODE_NO_ERROR:
        return DNS_OK;
    case DNS_RCODE_NXDOMAIN:
        return DNS_NXDOMAIN;
    default:
        return DNS_SERVER_ERROR;
    }
}
