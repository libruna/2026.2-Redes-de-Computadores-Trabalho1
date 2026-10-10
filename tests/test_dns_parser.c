#include "dns_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;
#define CHECK(c, m) do { if (c) printf("PASS %s\n", m); else { printf("FAIL %s\n", m); fails++; } } while (0)

// respostas reais do servidor 8.8.8.8 capturadas em 2026-10-09
static const uint8_t mx_ok[] = {
    0x12,0x34,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,               // cabecalho
    0x03,'u','n','b',0x02,'b','r',0x00,0x00,0x0f,0x00,0x01,                    // pergunta MX IN
    0xc0,0x0c,0x00,0x0f,0x00,0x01,0x00,0x00,0x0a,0x4f,0x00,0x26,               // resposta no offset 24
    0x00,0x00,0x06,'u','n','b','-','b','r',0x04,'m','a','i','l',               // preferencia e servidor
    0x0a,'p','r','o','t','e','c','t','i','o','n',0x07,'o','u','t','l','o','o','k',0x03,'c','o','m',0x00};
static const uint8_t nxdomain[] = {
    0x12,0x34,0x81,0x83,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,               // cabecalho com uma autoridade
    0x0f,'i','m','a','g','d','a','s','k','d','a','s','d','a','s','j',          // pergunta
    0x02,'b','r',0x00,0x00,0x0f,0x00,0x01,
    0xc0,0x1c,0x00,0x06,0x00,0x01,0x00,0x00,0x03,0x84,0x00,0x32,               // registro SOA de autoridade
    0x01,0x61,0x03,0x64,0x6e,0x73,0xc0,0x1c,0x0a,0x68,0x6f,0x73,               // RDATA do SOA
    0x74,0x6d,0x61,0x73,0x74,0x65,0x72,0x08,0x72,0x65,0x67,0x69,
    0x73,0x74,0x72,0x6f,0xc0,0x1c,0x78,0xc6,0xa0,0x22,0x00,0x00,
    0x07,0x08,0x00,0x00,0x03,0x84,0x00,0x09,0x3a,0x80,0x00,0x00,
    0x03,0x84};

// fga.unb.br responde com CNAME, sem registro MX
static const uint8_t no_mx[] = {
    0x12,0x34,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x00,
    0x03,0x66,0x67,0x61,0x03,0x75,0x6e,0x62,0x02,0x62,0x72,0x00,
    0x00,0x0f,0x00,0x01,0xc0,0x0c,0x00,0x05,0x00,0x01,0x00,0x00,
    0x06,0xad,0x00,0x07,0x04,0x66,0x63,0x74,0x65,0xc0,0x10,0xc0,
    0x10,0x00,0x06,0x00,0x01,0x00,0x00,0x07,0x08,0x00,0x28,0x04,
    0x64,0x6e,0x73,0x31,0xc0,0x10,0x0a,0x68,0x6f,0x73,0x74,0x6d,
    0x61,0x73,0x74,0x65,0x72,0xc0,0x10,0x78,0xc3,0xd8,0xa7,0x00,
    0x00,0x38,0x40,0x00,0x00,0x0e,0x10,0x00,0x12,0x75,0x00,0x00,
    0x00,0x0e,0x10};

// gmail.com possui cinco registros MX fora da ordem de preferencia
static const uint8_t multi_mx[] = {
    0x12,0x34,0x81,0x80,0x00,0x01,0x00,0x05,0x00,0x00,0x00,0x00,
    0x05,0x67,0x6d,0x61,0x69,0x6c,0x03,0x63,0x6f,0x6d,0x00,0x00,
    0x0f,0x00,0x01,0xc0,0x0c,0x00,0x0f,0x00,0x01,0x00,0x00,0x06,
    0x5f,0x00,0x1b,0x00,0x05,0x0d,0x67,0x6d,0x61,0x69,0x6c,0x2d,
    0x73,0x6d,0x74,0x70,0x2d,0x69,0x6e,0x01,0x6c,0x06,0x67,0x6f,
    0x6f,0x67,0x6c,0x65,0xc0,0x12,0xc0,0x0c,0x00,0x0f,0x00,0x01,
    0x00,0x00,0x06,0x5f,0x00,0x09,0x00,0x0a,0x04,0x61,0x6c,0x74,
    0x31,0xc0,0x29,0xc0,0x0c,0x00,0x0f,0x00,0x01,0x00,0x00,0x06,
    0x5f,0x00,0x09,0x00,0x1e,0x04,0x61,0x6c,0x74,0x33,0xc0,0x29,
    0xc0,0x0c,0x00,0x0f,0x00,0x01,0x00,0x00,0x06,0x5f,0x00,0x09,
    0x00,0x14,0x04,0x61,0x6c,0x74,0x32,0xc0,0x29,0xc0,0x0c,0x00,
    0x0f,0x00,0x01,0x00,0x00,0x06,0x5f,0x00,0x09,0x00,0x28,0x04,
    0x61,0x6c,0x74,0x34,0xc0,0x29};

static dns_status_t run_mx(const uint8_t *src, size_t len, uint16_t id, dns_mx_list_t *list) {

    uint8_t *buf = malloc(len ? len : 1);
    memcpy(buf, src, len);
    dns_status_t st = dns_parser_parse_mx(buf, len, id, list);
    free(buf);
    return st;
}

static dns_status_t run_record(const uint8_t *src, size_t len, size_t offset, dns_record_t *r, size_t *next) {

    uint8_t *buf = malloc(len ? len : 1);
    memcpy(buf, src, len);
    dns_status_t st = dns_parser_read_record(buf, len, offset, r, next);
    free(buf);
    return st;
}

static dns_status_t run_question(const uint8_t *src, size_t len, size_t offset, size_t *next) {

    uint8_t *buf = malloc(len ? len : 1);
    memcpy(buf, src, len);
    dns_status_t st = dns_parser_skip_question(buf, len, offset, next);
    free(buf);
    return st;
}

static dns_status_t run_name(const uint8_t *src, size_t len, size_t offset, char *name, size_t name_size, size_t *next) {

    // usa o tamanho exato para o ASan detectar leituras alem do pacote
    uint8_t *buf = malloc(len ? len : 1);
    memcpy(buf, src, len);
    dns_status_t st = dns_parser_read_name(buf, len, offset, name, name_size, next);
    free(buf);
    return st;
}

static dns_status_t run(const uint8_t *src, size_t len, uint16_t id, dns_header_t *h) {

    // usa o tamanho exato para o ASan detectar leituras alem do pacote
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

    // leitura de nomes
    char name[DNS_MAX_NAME_SIZE];
    size_t next = 0;
    size_t total = sizeof(mx_ok);

    CHECK(run_name(mx_ok, total, 12, name, sizeof(name), &next) == DNS_OK && strcmp(name, "unb.br") == 0 && next == 20,
          "nome simples: unb.br, termina no offset 20");
    CHECK(run_name(mx_ok, total, 24, name, sizeof(name), &next) == DNS_OK && strcmp(name, "unb.br") == 0 && next == 26,
          "ponteiro c0 0c: unb.br, proximo campo no offset 26");
    CHECK(run_name(mx_ok, total, 38, name, sizeof(name), &next) == DNS_OK &&
          strcmp(name, "unb-br.mail.protection.outlook.com") == 0 && next == total,
          "nome do servidor MX real");

    int trunc_ok = 1;
    for (size_t len = 0; len < total; len++) trunc_ok &= run_name(mx_ok, len, 38, name, sizeof(name), &next) != DNS_OK;
    CHECK(trunc_ok, "pacote cortado em qualquer ponto -> erro, sem leitura fora");

    const uint8_t root[] = {0x00};
    CHECK(run_name(root, 1, 0, name, sizeof(name), &next) == DNS_OK && name[0] == '\0' && next == 1, "nome raiz vazio");

    // rotulo mail seguido de um ponteiro para com
    const uint8_t mixed[] = {0x03,'c','o','m',0x00, 0x04,'m','a','i','l',0xc0,0x00};
    CHECK(run_name(mixed, sizeof(mixed), 5, name, sizeof(name), &next) == DNS_OK && strcmp(name, "mail.com") == 0 && next == 12,
          "rotulo seguido de ponteiro: mail.com");

    // cadeia de ponteiros para tras
    const uint8_t chain[] = {0x03,'c','o','m',0x00, 0x01,'a',0xc0,0x00,0x00, 0xc0,0x05};
    CHECK(run_name(chain, sizeof(chain), 10, name, sizeof(name), &next) == DNS_OK && strcmp(name, "a.com") == 0 && next == 12,
          "cadeia de ponteiros para tras");

    uint8_t p2[sizeof(mx_ok)];
    memcpy(p2, mx_ok, total); p2[25] = 24;
    CHECK(run_name(p2, total, 24, name, sizeof(name), &next) == DNS_INVALID_RESPONSE, "ponteiro para si mesmo");
    memcpy(p2, mx_ok, total); p2[25] = 40;
    CHECK(run_name(p2, total, 24, name, sizeof(name), &next) == DNS_INVALID_RESPONSE, "ponteiro para frente");

    // rotulo e ponteiro formam um ciclo
    const uint8_t loop[] = {0x02,'a','b',0xc0,0x00};
    CHECK(run_name(loop, sizeof(loop), 0, name, sizeof(name), &next) == DNS_INVALID_RESPONSE, "laco rotulo -> ponteiro -> rotulo");

    memcpy(p2, mx_ok, total); p2[25] = 0xFF; p2[24] = 0xFF;
    CHECK(run_name(p2, total, 24, name, sizeof(name), &next) == DNS_INVALID_RESPONSE, "ponteiro fora do pacote");
    const uint8_t half_ptr[] = {0xc0};
    CHECK(run_name(half_ptr, 1, 0, name, sizeof(name), &next) == DNS_INVALID_RESPONSE, "ponteiro com 1 byte so");
    const uint8_t reserved1[] = {0x40,0x00}, reserved2[] = {0x80,0x00};
    CHECK(run_name(reserved1, 2, 0, name, sizeof(name), &next) == DNS_INVALID_RESPONSE &&
          run_name(reserved2, 2, 0, name, sizeof(name), &next) == DNS_INVALID_RESPONSE, "prefixos reservados 0x40 e 0x80");
    CHECK(run_name(mx_ok, total, total, name, sizeof(name), &next) == DNS_INVALID_RESPONSE, "offset no fim do pacote");

    // quatro rotulos de 63 ultrapassam o limite de 255 bytes
    uint8_t big[4 * 64 + 1] = {0};
    for (int i = 0; i < 4; i++) { big[i * 64] = 63; memset(big + i * 64 + 1, 'x', 63); }
    CHECK(run_name(big, sizeof(big), 0, name, sizeof(name), &next) == DNS_INVALID_RESPONSE, "nome acima de 255 bytes");
    // tres rotulos de 63 e um de 61 atingem o limite exato
    big[3 * 64] = 61; big[3 * 64 + 62] = 0;
    CHECK(run_name(big, 3 * 64 + 63, 0, name, sizeof(name), &next) == DNS_OK && strlen(name) == 253, "nome no limite de 255 bytes");

    CHECK(run_name(mx_ok, total, 38, name, 10, &next) == DNS_INVALID_ARGUMENT, "buffer de saida pequeno");
    CHECK(dns_parser_read_name(NULL, 1, 0, name, sizeof(name), &next) == DNS_INVALID_ARGUMENT &&
          dns_parser_read_name(mx_ok, total, 12, NULL, 10, &next) == DNS_INVALID_ARGUMENT &&
          dns_parser_read_name(mx_ok, total, 12, name, 0, &next) == DNS_INVALID_ARGUMENT &&
          dns_parser_read_name(mx_ok, total, 12, name, sizeof(name), NULL) == DNS_INVALID_ARGUMENT, "argumentos NULL ou zero");

    // perguntas e registros
    dns_record_t rec;
    size_t nx_total = sizeof(nxdomain);

    CHECK(run_question(mx_ok, total, 12, &next) == DNS_OK && next == 24, "pula question do unb.br (12 -> 24)");
    CHECK(run_question(nxdomain, nx_total, 12, &next) == DNS_OK && next == 36, "pula question do inexistente (12 -> 36)");
    CHECK(run_question(mx_ok, 22, 12, &next) == DNS_INVALID_RESPONSE, "question sem QTYPE/QCLASS completos");

    CHECK(run_record(mx_ok, total, 24, &rec, &next) == DNS_OK && strcmp(rec.name, "unb.br") == 0 && rec.type == 15 &&
          rec.rr_class == 1 && rec.ttl == 2639 && rec.rdata_length == 38 && rec.rdata_offset == 36 && next == total,
          "registro MX real: campos e fim no offset 74");
    CHECK(run_record(nxdomain, nx_total, 36, &rec, &next) == DNS_OK && strcmp(rec.name, "br") == 0 && rec.type == 6 &&
          rec.ttl == 900 && rec.rdata_length == 50 && rec.rdata_offset == 48 && next == nx_total,
          "registro SOA real atravessado sem interpretar RDATA");

    // percorre a resposta NXDOMAIN usando os contadores do cabecalho
    dns_header_t nh;
    dns_parser_read_header(nxdomain, nx_total, 0x1234, &nh);
    size_t pos = 12;
    int walk_ok = run_question(nxdomain, nx_total, pos, &pos) == DNS_OK;
    for (int i = 0; i < nh.answer_count + nh.authority_count + nh.additional_count; i++) {
        walk_ok &= run_record(nxdomain, nx_total, pos, &rec, &pos) == DNS_OK;
    }
    CHECK(walk_ok && pos == nx_total, "percorre a resposta inteira pelos contadores");

    int rec_trunc_ok = 1;
    for (size_t len = 0; len < total; len++) rec_trunc_ok &= run_record(mx_ok, len, 24, &rec, &next) != DNS_OK;
    CHECK(rec_trunc_ok, "registro cortado em qualquer ponto -> erro, sem leitura fora");

    memcpy(p2, mx_ok, total); p2[35] = 39;
    CHECK(run_record(p2, total, 24, &rec, &next) == DNS_INVALID_RESPONSE, "RDLENGTH 1 byte maior que o pacote");
    memcpy(p2, mx_ok, total); p2[34] = 0xFF; p2[35] = 0xFF;
    CHECK(run_record(p2, total, 24, &rec, &next) == DNS_INVALID_RESPONSE, "RDLENGTH 65535");
    memcpy(p2, mx_ok, total); p2[30] = 0xFF;
    CHECK(run_record(p2, total, 24, &rec, &next) == DNS_OK && rec.ttl == 0xFF000a4fu, "TTL com bit alto (sem UB)");
    memcpy(p2, mx_ok, total); p2[25] = 24;
    CHECK(run_record(p2, total, 24, &rec, &next) == DNS_INVALID_RESPONSE, "NAME invalido propaga o erro");

    CHECK(dns_parser_read_record(NULL, total, 24, &rec, &next) == DNS_INVALID_ARGUMENT &&
          dns_parser_read_record(mx_ok, total, 24, NULL, &next) == DNS_INVALID_ARGUMENT &&
          dns_parser_read_record(mx_ok, total, 24, &rec, NULL) == DNS_INVALID_ARGUMENT &&
          dns_parser_skip_question(NULL, total, 12, &next) == DNS_INVALID_ARGUMENT &&
          dns_parser_skip_question(mx_ok, total, 12, NULL) == DNS_INVALID_ARGUMENT, "argumentos NULL (record/question)");

    // extracao dos registros MX
    static dns_mx_list_t list;

    CHECK(run_mx(mx_ok, total, 0x1234, &list) == DNS_OK && list.count == 1 && list.records[0].preference == 0 &&
          strcmp(list.records[0].exchange, "unb-br.mail.protection.outlook.com") == 0,
          "unb.br real: 1 MX, unb-br.mail.protection.outlook.com");
    CHECK(run_mx(nxdomain, nx_total, 0x1234, &list) == DNS_NXDOMAIN && list.count == 0, "inexistente real: DNS_NXDOMAIN");
    CHECK(run_mx(no_mx, sizeof(no_mx), 0x1234, &list) == DNS_NO_MX && list.count == 0, "fga.unb.br real: CNAME sem MX -> DNS_NO_MX");

    const uint16_t gmail_pref[] = {5, 10, 30, 20, 40};
    const char *gmail_names[] = {"gmail-smtp-in.l.google.com", "alt1.gmail-smtp-in.l.google.com",
                                 "alt3.gmail-smtp-in.l.google.com", "alt2.gmail-smtp-in.l.google.com",
                                 "alt4.gmail-smtp-in.l.google.com"};
    int gmail_ok = run_mx(multi_mx, sizeof(multi_mx), 0x1234, &list) == DNS_OK && list.count == 5;
    for (size_t i = 0; gmail_ok && i < 5; i++) {
        gmail_ok &= list.records[i].preference == gmail_pref[i] && strcmp(list.records[i].exchange, gmail_names[i]) == 0;
    }
    CHECK(gmail_ok, "gmail.com real: 5 MX na ordem do pacote, com compressao no RDATA");

    int mx_trunc_ok = 1;
    for (size_t len = 0; len < sizeof(multi_mx); len++) mx_trunc_ok &= run_mx(multi_mx, len, 0x1234, &list) != DNS_OK;
    CHECK(mx_trunc_ok, "gmail cortado em qualquer ponto -> erro, sem leitura fora");

    CHECK(run_mx(mx_ok, total, 0x4321, &list) == DNS_INVALID_RESPONSE, "ID divergente no parse_mx");
    memcpy(p2, mx_ok, total); p2[6] = 0xFF; p2[7] = 0xFF;
    CHECK(run_mx(p2, total, 0x1234, &list) == DNS_INVALID_RESPONSE, "ANCOUNT 65535 com 1 registro real");
    memcpy(p2, mx_ok, total); p2[35] = 37;
    CHECK(run_mx(p2, total, 0x1234, &list) == DNS_INVALID_RESPONSE, "RDLENGTH nao bate com o nome do MX");
    memcpy(p2, mx_ok, total); p2[35] = 2;
    CHECK(run_mx(p2, total, 0x1234, &list) == DNS_INVALID_RESPONSE, "RDATA de MX curto demais");
    memcpy(p2, mx_ok, total); p2[29] = 3;
    CHECK(run_mx(p2, total, 0x1234, &list) == DNS_NO_MX, "MX de classe CH (nao IN) e ignorado");

    // limita uma resposta com 17 registros ao maximo armazenado
    uint8_t many[24 + 17 * 16];
    memcpy(many, mx_ok, 24);
    many[7] = 17;
    for (int i = 0; i < 17; i++) {
        const uint8_t rr[16] = {0xc0,0x0c,0x00,0x0f,0x00,0x01,0,0,0,60,0x00,0x04,0x00,(uint8_t)i,0xc0,0x0c};
        memcpy(many + 24 + i * 16, rr, 16);
    }
    CHECK(run_mx(many, sizeof(many), 0x1234, &list) == DNS_OK && list.count == DNS_MAX_MX_RECORDS &&
          list.records[15].preference == 15 && strcmp(list.records[15].exchange, "unb.br") == 0,
          "17 MX: guarda 16 sem estourar a lista");

    CHECK(dns_parser_parse_mx(NULL, total, 0x1234, &list) == DNS_INVALID_ARGUMENT &&
          dns_parser_parse_mx(mx_ok, total, 0x1234, NULL) == DNS_INVALID_ARGUMENT, "argumentos NULL (parse_mx)");

    printf("%d falha(s)\n", fails);
    return fails != 0;
}
