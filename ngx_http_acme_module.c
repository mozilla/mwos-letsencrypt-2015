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


#define HELLO_WORLD "hello world"
#define CERT_PATH "conf/cert.crt"
#define KEY_PATH "conf/priv.key"
#define FROM_CERT_PATH "../conf/cert.crt"
#define FROM_KEY_PATH "../conf/priv.key"

static ngx_int_t ngx_http_acme_handler(ngx_http_request_t *r);
static char *ngx_http_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/**
 * This module provided directive: acme.
 *
 */
static ngx_command_t ngx_http_acme_commands[] = {

    { ngx_string("acme"), /* directive */
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS, /* location context and takes
                                            no arguments*/
      ngx_http_acme, /* configuration setup function */
      0, /* No offset. Only one context is supported. */
      0, /* No offset when storing the module configuration on struct. */
      NULL},

    ngx_null_command /* command termination */
};

/* The hello world string. */
static u_char ngx_hello_world[] = HELLO_WORLD;

/* The module context. */
static ngx_http_module_t ngx_http_acme_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

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
 * Content handler.
 *
 * @param r
 *   Pointer to the request structure. See http_request.h.
 * @return
 *   The status of the response generation.
 */
static ngx_int_t ngx_http_acme_handler(ngx_http_request_t *r)
{
    ngx_buf_t *b;
    ngx_chain_t out;

    /* Set the Content-Type header. */
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";

    /* Allocate a new buffer for sending out the reply. */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    /* Insertion in the buffer chain. */
    out.buf = b;
    out.next = NULL; /* just one buffer */

    b->pos = ngx_hello_world; /* first position in memory of the data */
    b->last = ngx_hello_world + sizeof(ngx_hello_world); /* last position in memory of the data */
    b->memory = 1; /* content is in read-only memory */
    b->last_buf = 1; /* there will be no more buffers in the request */

    /* Sending the headers for the reply. */
    r->headers_out.status = NGX_HTTP_OK; /* 200 status code */
    /* Get the content length of the body. */
    r->headers_out.content_length_n = sizeof(ngx_hello_world);
    ngx_http_send_header(r); /* Send the headers */

    /* Send the body, and return the status code of the output filter chain. */
    return ngx_http_output_filter(r, &out);
} /* ngx_http_acme_handler */

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
    ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */
    ngx_copy_file_t   cpyf;
    int ret;

    /* Install the acme handler. */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_acme_handler;

    /* Install a certificate */

    // TODO (KK) Derive FROM_CERT_PATH and FROM_KEY_PATH from SSL module

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
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Copying the certificate or private key in place failed");
        return NGX_CONF_ERROR;
    }

    /* End certificate installation */

    return NGX_CONF_OK;
} /* ngx_http_hello_world */

