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

#include <curl/curl.h>
#include <jansson.h>

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
#define ACME_SERVER "https://acme-staging.api.letsencrypt.org"

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
static char *ngx_http_acme_fetch_dir(ngx_conf_t *cf, void *conf);
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
    int ret;

    // TODO: Pull the different parts out as own methods for readability

    /*
     * TODO: Get the config directory path (e.g. /etc/nginx)
     */


    /*
     * TODO: Init acme dir (mkdirs)
     */


    /*
     * TODO: Generate key pair for ACME authorization
     */
    RSA *rsa = NULL;
    BIGNUM *e = NULL;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Generate RSA key");

    // TODO: Check the return codes (ret)
    rsa = RSA_new();
    ret = BN_dec2bn(&e, ACME_ACCOUNT_RSA_EXP);
    ret = RSA_generate_key_ex(rsa, ACME_ACCOUNT_RSA_BITS, e, NULL);


    RSA_free(rsa);
    BN_free(e);

    /*
     * TODO: Install certificate (right now it just copies an example cert)
     */
    ngx_copy_file_t   cpyf;

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
     * TODO: ACME stuff
     */
    ngx_http_acme_fetch_dir(cf, conf);

    /*
     * Fool the SSL module into using the ACME certificates
     */
    // Get SSL module configuration
    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

    // TODO (KK) Report warning when ssl configs are not set (acme w/o ssl activated in the same server context is an error)
    // --> Maybe ignore acme config then and issue a warning

    if(sscf) {
//        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Found SSL certificate path: %s", sscf->certificate.data);

        // Spoof SSL cert
        ngx_str_set(&sscf->certificate, ACME_DIR "/" ACME_LIVE_DIR "/" ACME_DEV_SERVER_NAME "/" ACME_CERT);
        ngx_str_set(&sscf->certificate_key, ACME_DIR "/" ACME_LIVE_DIR "/" ACME_DEV_SERVER_NAME "/" ACME_CERT_KEY);
    }


    return NGX_CONF_OK;
} /* ngx_http_acme */


static char *ngx_http_acme_fetch_dir(ngx_conf_t *cf, void *conf)
{
    CURL *curl;
    CURLcode res;

    FILE *data_stream;
    ngx_str_t data;

    json_t *root;
    json_error_t error;

    /* Begin cURL part */

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, ACME_SERVER "/directory");

        /* Setup the stream for the reponse data */
        data_stream = open_memstream((char **) &data.data, &data.len);

        if(data_stream != NULL) {

            curl_easy_setopt(curl, CURLOPT_WRITEDATA, data_stream);

            /* Perform the request, res will get the return code */
            res = curl_easy_perform(curl);
            /* Check for errors */
            if(res != CURLE_OK)
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        /* always cleanup */
        curl_easy_cleanup(curl);

        // Null terminate the future string
        fputc('\0', data_stream);
        fclose(data_stream);
    }

    //    curl_global_cleanup();

    /* End cURL part */

    /* Now all the returned JSON is in the data variable */

    /*
     * Parsing returned JSON
     */
    fwrite(data.data, sizeof(char), data.len, stdout);
    printf("\n");
    fflush(stdout);

    /* Begin Jansson part */

    root = json_loads((char *) data.data, 0, &error);
    free(data.data);

    if(!root)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                "Error parsing JSON: on line %d: %s\n", error.line, error.text);
        return NGX_CONF_ERROR;
    }

    /* The part below is different for each ACME request */

    if(!json_is_object(root)) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                "Error parsing JSON: directory data is not an object\n");
        json_decref(root);
        return NGX_CONF_ERROR;
    }

    // TODO extract the JSON to a custom data type

    json_decref(root);

    /* End Jansson part */

    return NGX_CONF_OK;
}

/**
 * TODO: delete
 * This entry point is too late, we will probably never use it.
 */
static ngx_int_t ngx_http_acme_init(ngx_conf_t *cf)
{
    return NGX_OK;
}
