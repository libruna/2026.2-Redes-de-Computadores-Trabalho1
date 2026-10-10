#include "dns_protocol.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c, m) do { if (c) printf("PASS %s\n", m); else { printf("FAIL %s\n", m); fails++; } } while (0)

static void test_domain_validation(void) {

    CHECK(dns_protocol_is_valid_domain("unb.br"), "dominio simples");
    CHECK(dns_protocol_is_valid_domain("mail.unb.br"), "tres rotulos");
    CHECK(dns_protocol_is_valid_domain("mx-1.Example.COM"), "letras, digitos e hifen");
    CHECK(dns_protocol_is_valid_domain("unb.br."), "ponto final opcional");

    CHECK(!dns_protocol_is_valid_domain(NULL), "dominio NULL");
    CHECK(!dns_protocol_is_valid_domain(""), "dominio vazio");
    CHECK(!dns_protocol_is_valid_domain("."), "nome raiz sem dominio");
    CHECK(!dns_protocol_is_valid_domain(".unb.br"), "ponto inicial");
    CHECK(!dns_protocol_is_valid_domain("unb..br"), "rotulo vazio");
    CHECK(!dns_protocol_is_valid_domain("-unb.br"), "hifen no inicio");
    CHECK(!dns_protocol_is_valid_domain("unb-.br"), "hifen no fim");
    CHECK(!dns_protocol_is_valid_domain("unb_br"), "caractere nao permitido");

    char long_label[DNS_MAX_LABEL_SIZE + 2];
    memset(long_label, 'a', sizeof(long_label) - 1);
    long_label[sizeof(long_label) - 1] = '\0';
    CHECK(!dns_protocol_is_valid_domain(long_label), "rotulo maior que 63 bytes");

    char maximum_domain[DNS_MAX_DOMAIN_SIZE + 1];
    size_t offset = 0;
    const size_t label_sizes[] = {63, 63, 63, 61};
    for (size_t label = 0; label < 4; ++label) {
        if (label > 0) {
            maximum_domain[offset++] = '.';
        }
        memset(maximum_domain + offset, 'a', label_sizes[label]);
        offset += label_sizes[label];
    }
    maximum_domain[offset] = '\0';
    CHECK(offset == DNS_MAX_DOMAIN_SIZE &&
          dns_protocol_is_valid_domain(maximum_domain),
          "dominio no limite de 253 caracteres");

    char oversized_domain[DNS_MAX_DOMAIN_SIZE + 2];
    memcpy(oversized_domain, maximum_domain, DNS_MAX_DOMAIN_SIZE);
    oversized_domain[DNS_MAX_DOMAIN_SIZE] = 'a';
    oversized_domain[DNS_MAX_DOMAIN_SIZE + 1] = '\0';
    CHECK(!dns_protocol_is_valid_domain(oversized_domain),
          "dominio acima de 253 caracteres");
}

static void test_query_bytes(void) {

    static const uint8_t expected[] = {
        0x12, 0x34,             // identificador da transacao
        0x01, 0x00,             // consulta recursiva
        0x00, 0x01,             // uma pergunta
        0x00, 0x00,             // zero respostas
        0x00, 0x00,             // zero autoridades
        0x00, 0x00,             // zero adicionais
        0x03, 'u', 'n', 'b',    // unb
        0x02, 'b', 'r',         // br
        0x00,                   // fim do nome
        0x00, 0x0F,             // tipo MX
        0x00, 0x01              // classe IN
    };

    uint8_t query[DNS_MAX_MESSAGE_SIZE];
    size_t query_size = 0;
    dns_status_t status = dns_protocol_build_mx_query("unb.br", 0x1234, query, sizeof(query), &query_size);

    CHECK(status == DNS_OK, "monta consulta de unb.br");
    CHECK(query_size == sizeof(expected), "calcula tamanho exato da consulta");
    CHECK(memcmp(query, expected, sizeof(expected)) == 0, "cabecalho, QNAME, QTYPE e QCLASS byte a byte");

    uint8_t absolute_query[sizeof(expected)];
    size_t absolute_size = 0;
    status = dns_protocol_build_mx_query("unb.br.", 0x1234, absolute_query, sizeof(absolute_query), &absolute_size);
    CHECK(status == DNS_OK && absolute_size == sizeof(expected) &&
          memcmp(absolute_query, expected, sizeof(expected)) == 0,
          "ponto final nao altera o QNAME");
}

static void test_errors_and_limits(void) {

    uint8_t query[DNS_MAX_MESSAGE_SIZE];
    size_t query_size = 99;

    CHECK(dns_protocol_build_mx_query(NULL, 1, query, sizeof(query), &query_size) == DNS_INVALID_ARGUMENT &&
          query_size == 0, "dominio NULL");
    CHECK(dns_protocol_build_mx_query("unb.br", 1, NULL, sizeof(query), &query_size) == DNS_INVALID_ARGUMENT &&
          query_size == 0, "buffer NULL");
    CHECK(dns_protocol_build_mx_query("unb..br", 1, query, sizeof(query), &query_size) == DNS_INVALID_DOMAIN &&
          query_size == 0, "dominio malformado");
    CHECK(dns_protocol_build_mx_query("unb.br", 1, query, 23, &query_size) == DNS_BUFFER_TOO_SMALL &&
          query_size == 0, "buffer um byte menor que a consulta");
    CHECK(dns_protocol_build_mx_query("unb.br", 1, query, 24, &query_size) == DNS_OK &&
          query_size == 24, "buffer com tamanho exato");
    CHECK(dns_protocol_build_mx_query("unb.br", 1, query, sizeof(query), NULL) == DNS_INVALID_ARGUMENT,
          "ponteiro de tamanho NULL");

    uint16_t transaction_id = 0;
    CHECK(dns_protocol_generate_transaction_id(&transaction_id) == DNS_OK, "gera Transaction ID de 16 bits");
    CHECK(dns_protocol_generate_transaction_id(NULL) == DNS_INVALID_ARGUMENT, "Transaction ID NULL");
}

int main(void) {

    test_domain_validation();
    test_query_bytes();
    test_errors_and_limits();

    printf("%d falha(s)\n", fails);
    return fails != 0;
}
