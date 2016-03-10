/*
 * ngx_http_acme_module.h
 *
 *  Created on: Feb 26, 2016
 *      Author: klaus
 */

#ifndef NGX_HTTP_ACME_MODULE_H_
#define NGX_HTTP_ACME_MODULE_H_

/*
 * Makros which could also form config directives later
 */
#define ACME_DIR "acme"
#define ACME_LIVE_DIR "live"
#define ACME_CERT_TRUSTED "chain.pem"
#define ACME_CERT_KEY "privkey.pem"
#define ACME_CERT "fullchain.pem"
#define ACME_ACCOUNT_RSA_BITS 2048
#define ACME_ACCOUNT_RSA_EXP "65537"
#define ACME_SERVER_DOMAIN "acme-staging.api.letsencrypt.org"
#define ACME_SERVER "https://" ACME_SERVER_DOMAIN


typedef enum {
    GET,
    POST
} ngx_http_acme_http_method_t;


#define ngx_string_dynamic(str)     { strlen(str), (u_char *) str }

#endif /* NGX_HTTP_ACME_MODULE_H_ */
