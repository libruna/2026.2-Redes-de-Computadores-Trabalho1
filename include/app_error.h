#ifndef APP_ERROR_H
#define APP_ERROR_H

//issue 16: Definir enum de erros compartilhado
typedef enum {
    APP_RESULT_SUCCESS = 0,
    APP_ERROR_ARGUMENTS,
    APP_ERROR_DOMAIN,
    APP_ERROR_IP,
    APP_ERROR_NO_RESPONSE,
    APP_ERROR_NXDOMAIN,
    APP_ERROR_NO_MX,
    APP_ERROR_DNS_RESPONSE,
    APP_ERROR_INTERNAL
} app_result_t;

#endif
