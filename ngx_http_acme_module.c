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

/*
 * Makros which could also form config directives later
 */
#define ACME_DIR "acme"
#define ACME_LIVE_DIR "live"
#define ACME_CERT_TRUSTED "chain.pem"
#define ACME_CERT_KEY "privkey.pem"
#define ACME_CERT "fullchain.pem"

/*
 * Temporary dev makros
 */
// This should later be gathered from nginx
#define ACME_DEV_CONF_DIR "conf"
// This should later be replaced with the value of the server_name directive of the core module
#define ACME_DEV_SERVER_NAME "ledev2.kbauer.at"

#define ACME_DEV_CERT_PATH (ACME_DEV_CONF_DIR "/" ACME_DIR "/" ACME_LIVE_DIR "/" ACME_DEV_SERVER_NAME "/" ACME_CERT)
#define ACME_DEV_KEY_PATH (ACME_DEV_CONF_DIR "/" ACME_DIR "/" ACME_LIVE_DIR "/" ACME_DEV_SERVER_NAME "/" ACME_CERT_KEY)
#define ACME_DEV_EXAMPLE_DIR "../example"
#define ACME_DEV_FROM_CERT_PATH (ACME_DEV_EXAMPLE_DIR "/cert.pem")
#define ACME_DEV_FROM_KEY_PATH (ACME_DEV_EXAMPLE_DIR "/cert-key.pem")


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
    ngx_http_ssl_srv_conf_t *sscf; /* pointer to core location configuration */
    ngx_copy_file_t   cpyf;
    int ret;

    /*
     * TODO: Get the config directory path (e.g. /etc/nginx)
     */


    /*
     * TODO: Init acme dir (mkdirs)
     */


    /*
     * TODO: Generate key pair for ACME authorization
     */


    /*
     * TODO: Install certificate (right now it just copies an example cert)
     */
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Installing certificate and key");

    cpyf.size = -1;
    cpyf.buf_size = 0;
    cpyf.access =  NGX_FILE_DEFAULT_ACCESS;
    cpyf.time = -1;
    cpyf.log = cf->log;

    // Copy certificate
    ret = ngx_copy_file((u_char *)ACME_DEV_FROM_CERT_PATH, (u_char *)ACME_DEV_CERT_PATH, &cpyf);

    // Copy private key
    if(ret == NGX_OK) {
        // Only 0600 access for private key
        cpyf.access = NGX_FILE_OWNER_ACCESS;

        ret = ngx_copy_file((u_char *)ACME_DEV_FROM_KEY_PATH, (u_char *)ACME_DEV_KEY_PATH, &cpyf);
    }

    if(ret != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "Installing the certificate or private key failed");
        return NGX_CONF_ERROR;
    }

    /*
     * Fool the SSL module into using the ACME certificates
     */
    // Get SSL module configuration
    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

    // TODO (KK) Report error when ssl configs are not set (acme w/o ssl configured in the same server context is an error)

    if(sscf) {
//        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Found SSL certificate path: %s", sscf->certificate.data);

        // Spoof SSL cert
        ngx_str_set(&sscf->certificate, ACME_DIR "/" ACME_LIVE_DIR "/" ACME_DEV_SERVER_NAME "/" ACME_CERT);
        ngx_str_set(&sscf->certificate_key, ACME_DIR "/" ACME_LIVE_DIR "/" ACME_DEV_SERVER_NAME "/" ACME_CERT_KEY);
    }


    return NGX_CONF_OK;
} /* ngx_http_acme */

/**
 * TODO: delete
 * This entry point is too late, we will probably never use it.
 */
static ngx_int_t ngx_http_acme_init(ngx_conf_t *cf)
{
    return NGX_OK;
}
