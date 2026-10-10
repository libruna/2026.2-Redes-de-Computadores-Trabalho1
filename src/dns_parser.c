#include "dns_parser.h"
#include <stddef.h>
#include <string.h>

#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_TC 0x0200
#define DNS_RCODE_MASK 0x000F
#define DNS_RCODE_NO_ERROR 0
#define DNS_RCODE_NXDOMAIN 3

#define DNS_LABEL_TYPE_MASK 0xC0
#define DNS_LABEL_POINTER 0xC0
#define DNS_POINTER_OFFSET_MASK 0x3F
#define DNS_MAX_ENCODED_NAME_SIZE 255

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

dns_status_t dns_parser_read_name(const uint8_t *message, size_t message_size, size_t offset, char *name, size_t name_size,
                                  size_t *next_offset) {

    if (message == NULL || name == NULL || name_size == 0 || next_offset == NULL) {
        return DNS_INVALID_ARGUMENT;
    }

    size_t position = offset;
    // each pointer must jump before this, so the jumps cannot loop
    size_t segment_start = offset;
    size_t end_offset = 0;
    int jumped = 0;
    size_t encoded_size = 0;
    size_t name_length = 0;

    name[0] = '\0';

    for (;;) {
        if (position >= message_size) {
            return DNS_INVALID_RESPONSE;
        }

        uint8_t length = message[position];

        if ((length & DNS_LABEL_TYPE_MASK) == DNS_LABEL_POINTER) {
            if (position + 1 >= message_size) {
                return DNS_INVALID_RESPONSE;
            }

            size_t target = ((size_t)(length & DNS_POINTER_OFFSET_MASK) << 8) | message[position + 1];
            if (target >= segment_start) {
                return DNS_INVALID_RESPONSE;
            }

            if (!jumped) {
                end_offset = position + 2;
                jumped = 1;
            }

            position = target;
            segment_start = target;
            continue;
        }

        // 0x40 and 0x80 prefixes are reserved
        if ((length & DNS_LABEL_TYPE_MASK) != 0) {
            return DNS_INVALID_RESPONSE;
        }

        encoded_size += (size_t)length + 1;
        if (encoded_size > DNS_MAX_ENCODED_NAME_SIZE) {
            return DNS_INVALID_RESPONSE;
        }

        if (length == 0) {
            if (!jumped) {
                end_offset = position + 1;
            }
            *next_offset = end_offset;
            return DNS_OK;
        }

        if (position + 1 + length > message_size) {
            return DNS_INVALID_RESPONSE;
        }

        size_t separator = (name_length > 0) ? 1 : 0;
        if (name_length + separator + length + 1 > name_size) {
            return DNS_INVALID_ARGUMENT;
        }

        if (separator) {
            name[name_length++] = '.';
        }
        memcpy(name + name_length, message + position + 1, length);
        name_length += length;
        name[name_length] = '\0';

        position += 1 + (size_t)length;
    }
}
