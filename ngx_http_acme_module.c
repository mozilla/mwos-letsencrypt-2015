/**
 * @file   ngx_http_acme_module.c
 * @author Klaus Krapfenbauer <klaus.krapfenbauer@gmail.com>
 * @date   Fri Oct 30 14:57:23 UTC 2015
 *
 * @brief  An ACME module for Nginx.
 *
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define CERT_PATH "conf/cert.pem"
#define KEY_PATH "conf/cert.key"
#define FROM_CERT_PATH "../conf/cert.pem"
#define FROM_KEY_PATH "../conf/cert.key"

//static ngx_int_t ngx_http_acme_handler(ngx_http_request_t *r);
static char *ngx_http_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_acme_init(ngx_conf_t *cf);

/**
 * This module provided directive: acme.
 *
 */
static ngx_command_t ngx_http_acme_commands[] = {

    { ngx_string("acme"), /* directive */
      NGX_HTTP_SRV_CONF|NGX_CONF_NOARGS, /* location context and takes
                                            no arguments*/
      ngx_http_acme, /* configuration setup function */
      0, /* No offset. Only one context is supported. */
      0, /* No offset when storing the module configuration on struct. */
      NULL},

    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_acme_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_acme_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_acme_module = {
    NGX_MODULE_V1,
    &ngx_http_acme_module_ctx, /* module context */
    ngx_http_acme_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};


/**
 * Configuration setup function that installs the content handler.
 *
 * @param cf
 *   Module configuration structure pointer.
 * @param cmd
 *   Module directives structure pointer.
 * @param conf
 *   Module configuration structure pointer.
 * @return string
 *   Status of the configuration setup.
 */
static char *ngx_http_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
//    ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */
    ngx_copy_file_t   cpyf;
    int ret;

    /* Install the acme handler. */
//    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
//    clcf->handler = ngx_http_acme_handler;

    /* Begin certificate installation */

    // TODO (KK) Derive CERT_PATH and KEY_PATH from SSL module

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Copying certificate and key");

    cpyf.size = -1;
    cpyf.buf_size = 0;
    cpyf.access =  NGX_FILE_DEFAULT_ACCESS;
    cpyf.time = -1;
    cpyf.log = cf->log;

    // Copy certificate
    ret = ngx_copy_file((u_char *)FROM_CERT_PATH, (u_char *)CERT_PATH, &cpyf);

    // Copy private key
    if(ret == NGX_OK) {
        // Only 0600 access for private key
        cpyf.access = NGX_FILE_OWNER_ACCESS;

        ret = ngx_copy_file((u_char *)FROM_KEY_PATH, (u_char *)KEY_PATH, &cpyf);
    }

    if(ret != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "Copying the certificate or private key in place failed");
        return NGX_CONF_ERROR;
    }

    /* End certificate installation */

    return NGX_CONF_OK;
} /* ngx_http_acme */

/**
 * TODO: docu
 */
static ngx_int_t ngx_http_acme_init(ngx_conf_t *cf)
{
    return NGX_OK;
}
