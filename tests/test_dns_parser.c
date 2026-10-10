#include "dns_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;
#define CHECK(c, m) do { if (c) printf("PASS %s\n", m); else { printf("FAIL %s\n", m); fails++; } } while (0)

/* real responses from 8.8.8.8, captured 2026-10-09 (header + question only) */
static const uint8_t mx_ok[] = {0x12,0x34,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00};
static const uint8_t nxdomain[] = {0x12,0x34,0x81,0x83,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00};

static dns_status_t run(const uint8_t *src, size_t len, uint16_t id, dns_header_t *h) {
    /* exact-size heap copy so ASan catches any read past len */
    uint8_t *buf = malloc(len ? len : 1);
    memcpy(buf, src, len);
    dns_status_t st = dns_parser_read_header(buf, len, id, h);
    free(buf);
    return st;
}

int main(void) {
    dns_header_t h;
    uint8_t p[12];

    CHECK(run(mx_ok, 12, 0x1234, &h) == DNS_OK, "resposta real unb.br -> DNS_OK");
    CHECK(h.id == 0x1234 && h.flags == 0x8180 && h.question_count == 1 && h.answer_count == 1 &&
          h.authority_count == 0 && h.additional_count == 0, "contadores lidos corretamente");
    CHECK(run(nxdomain, 12, 0x1234, &h) == DNS_NXDOMAIN, "resposta real inexistente -> DNS_NXDOMAIN");
    CHECK(h.answer_count == 0 && h.authority_count == 1, "NXDOMAIN: AN=0, NS=1");

    int short_ok = 1;
    for (size_t len = 0; len < 12; len++) short_ok &= run(mx_ok, len, 0x1234, &h) == DNS_INVALID_RESPONSE;
    CHECK(short_ok, "pacotes de 0 a 11 bytes -> DNS_INVALID_RESPONSE");

    CHECK(run(mx_ok, 12, 0x1235, &h) == DNS_INVALID_RESPONSE, "ID divergente");
    memcpy(p, mx_ok, 12); p[2] &= 0x7F;
    CHECK(run(p, 12, 0x1234, &h) == DNS_INVALID_RESPONSE, "QR = 0");
    memcpy(p, mx_ok, 12); p[2] |= 0x02;
    CHECK(run(p, 12, 0x1234, &h) == DNS_INVALID_RESPONSE, "TC = 1");
    memcpy(p, mx_ok, 12); p[3] = (p[3] & 0xF0) | 2;
    CHECK(run(p, 12, 0x1234, &h) == DNS_SERVER_ERROR, "RCODE 2 (SERVFAIL)");
    memcpy(p, mx_ok, 12); p[3] = (p[3] & 0xF0) | 5;
    CHECK(run(p, 12, 0x1234, &h) == DNS_SERVER_ERROR, "RCODE 5 (REFUSED)");
    memcpy(p, mx_ok, 12); p[3] = 0x8F;
    CHECK(run(p, 12, 0x1234, &h) == DNS_SERVER_ERROR, "RCODE 15 (bits altos nao interferem)");
    memcpy(p, mx_ok, 12); p[0] = 0xFF; p[1] = 0xFF; p[4] = 0xFF; p[5] = 0xFE;
    CHECK(run(p, 12, 0xFFFF, &h) == DNS_OK && h.question_count == 0xFFFE, "valores altos sem estouro de sinal");

    CHECK(dns_parser_read_header(NULL, 12, 0x1234, &h) == DNS_INVALID_ARGUMENT, "response NULL");
    CHECK(dns_parser_read_header(mx_ok, 12, 0x1234, NULL) == DNS_INVALID_ARGUMENT, "header NULL");

    printf("%d falha(s)\n", fails);
    return fails != 0;
}
