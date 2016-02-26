/*
 * ngx_http_acme_lib.h
 *
 *  Created on: Feb 26, 2016
 *      Author: klaus
 */

#ifndef NGX_HTTP_ACME_LIB_H_
#define NGX_HTTP_ACME_LIB_H_

typedef struct {
    char *new_reg;
    char *recover_reg;
    char *new_authz;
    char *new_cert;
    char *revoke_cert;
    char *reg;
    char *authz;
    char *challenge;
    char *cert;
} acme_dir_t;

#endif /* NGX_HTTP_ACME_LIB_H_ */
