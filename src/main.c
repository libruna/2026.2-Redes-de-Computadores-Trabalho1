#include "app_error.h"
#include "dns_parser.h"
#include "dns_protocol.h"
#include "udp_client.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#define DNS_PACKET_CAPACITY 4096u

static int report_error(app_result_t result, const char *domain, const char *detail) {
    switch (result) {
    case APP_ERROR_ARGUMENTS:
        fprintf(stderr, "Uso: ./meu_cliente <dominio> <ipv4_dns>\n");
        break;
    case APP_ERROR_DOMAIN:
        fprintf(stderr, "Dominio invalido: %s\n", domain != NULL ? domain : "(nulo)");
        break;
    case APP_ERROR_IP:
        fprintf(stderr, "Endereco IPv4 invalido: %s\n", detail != NULL ? detail : "(nulo)");
        break;
    case APP_ERROR_NO_RESPONSE:
        printf("Nao foi possivel coletar entrada MX para %s\n", domain);
        break;
    case APP_ERROR_NXDOMAIN:
        printf("Dominio %s nao encontrado\n", domain);
        break;
    case APP_ERROR_NO_MX:
        printf("Dominio %s nao possui entrada MX\n", domain);
        break;
    case APP_ERROR_DNS_RESPONSE:
        fprintf(stderr, "Resposta DNS invalida ou erro retornado pelo servidor (%s)\n",
                detail != NULL ? detail : "erro desconhecido");
        break;
    case APP_ERROR_INTERNAL:
        fprintf(stderr, "Erro interno: %s\n", detail != NULL ? detail : "erro desconhecido");
        break;
    case APP_RESULT_SUCCESS:
        return 0;
    }
    return 1;
}

static const char *dns_status_name(dns_status_t status) {
    switch (status) {
    case DNS_OK: return "DNS_OK";
    case DNS_INVALID_ARGUMENT: return "argumento invalido";
    case DNS_INVALID_DOMAIN: return "dominio invalido";
    case DNS_BUFFER_TOO_SMALL: return "buffer insuficiente";
    case DNS_RANDOM_ERROR: return "falha ao gerar Transaction ID";
    case DNS_INVALID_RESPONSE: return "resposta DNS malformada";
    case DNS_NXDOMAIN: return "NXDOMAIN";
    case DNS_SERVER_ERROR: return "RCODE DNS diferente de NOERROR";
    case DNS_NO_MX: return "sem registro MX";
    }
    return "status DNS desconhecido";
}

int main(int argc, char **argv) {
    if (argc != 3) return report_error(APP_ERROR_ARGUMENTS, NULL, NULL);

    //valida o dominiop
    const char *domain = argv[1];
    const char *server_ip = argv[2];
    if (!dns_protocol_is_valid_domain(domain))
        return report_error(APP_ERROR_DOMAIN, domain, NULL);

    //verifica se formato e ipv4
    struct in_addr parsed_ip;
    if (inet_pton(AF_INET, server_ip, &parsed_ip) != 1)
        return report_error(APP_ERROR_IP, NULL, server_ip);

    //gerar transaction id
    uint16_t transaction_id = 0;
    dns_status_t dns_status = dns_protocol_generate_transaction_id(&transaction_id);
    if (dns_status != DNS_OK)
        return report_error(APP_ERROR_INTERNAL, domain, dns_status_name(dns_status));

    //consulta MX
    uint8_t query[DNS_PACKET_CAPACITY];
    size_t query_size = 0;
    dns_status = dns_protocol_build_mx_query(domain, transaction_id, query, sizeof(query), &query_size);
    if (dns_status != DNS_OK) {
        app_result_t error = dns_status == DNS_INVALID_DOMAIN ? APP_ERROR_DOMAIN : APP_ERROR_INTERNAL;
        return report_error(error, domain, dns_status_name(dns_status));
    }

    //abrir cliente udp
    udp_client_t client = {.socket_fd = -1};
    udp_client_status_t udp_status = udp_client_open(&client, server_ip);
    if (udp_status != UDP_CLIENT_OK) {
        return report_error(APP_ERROR_INTERNAL, domain, "nao foi possivel abrir socket UDP");
    }

    //envia consulta e recebe resposta
    uint8_t response[DNS_PACKET_CAPACITY];
    size_t response_size = 0;
    udp_status = udp_client_exchange(&client, query, query_size, response,
                                     sizeof(response), &response_size);
    udp_client_close(&client);

    if (udp_status != UDP_CLIENT_OK) {
        if (udp_status == UDP_CLIENT_TIMEOUT)
            return report_error(APP_ERROR_NO_RESPONSE, domain, NULL);
        return report_error(APP_ERROR_INTERNAL, domain, "falha na comunicacao UDP");
    }

    //interpretar repsosta DNS
    dns_mx_list_t mx_list;
    dns_status = dns_parser_parse_mx(response, response_size, transaction_id, &mx_list);
    if (dns_status == DNS_NXDOMAIN)
        return report_error(APP_ERROR_NXDOMAIN, domain, NULL);
    if (dns_status == DNS_NO_MX)
        return report_error(APP_ERROR_NO_MX, domain, NULL);
    if (dns_status != DNS_OK)
        return report_error(APP_ERROR_DNS_RESPONSE, domain, dns_status_name(dns_status));

    //pegar reg MX menor valor de preferencia
    size_t best = 0;
    for (size_t i = 1; i < mx_list.count; ++i) {
        if (mx_list.records[i].preference < mx_list.records[best].preference)
            best = i;
    }

    printf("%s <> %s\n", domain, mx_list.records[best].exchange);//print do MX
    return 0;
}
