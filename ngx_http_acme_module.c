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

#include <inttypes.h>
#include <string.h>

#include <curl/curl.h>
#include <jansson.h>

#include "ngx_http_acme_lib.h"
#include "ngx_http_acme_module.h"

/*
 * String constants
 */
#define ACME_REPLAY_NONCE_PREFIX_STRING ACME_REPLAY_NONCE_HEADER ": "
#define ACME_TOS_PREFIX_STRING "Link: <"
#define ACME_TOS_SUFFIX_STRING ">;rel=\"" ACME_TERMS_LINK_HEADER "\""
#define ACME_LOCATION_HEADER_PREFIX_STRING "Location: "

/*
 * Temporary dev macros
 */
/* Nginx config directory; This should later be gathered from nginx */
#define ACME_DEV_CONF_DIR "conf"
/* This should later be replaced with the value of the server_name directive of the core module */
#define ACME_DEV_SERVER_NAME "ledev2.kbauer.at"

#define ACME_DEV_CERT_PATH ACME_DEV_CONF_DIR "/" ACME_DIR "/" ACME_LIVE_DIR "/" ACME_DEV_SERVER_NAME "/" ACME_CERT
#define ACME_DEV_KEY_PATH ACME_DEV_CONF_DIR "/" ACME_DIR "/" ACME_LIVE_DIR "/" ACME_DEV_SERVER_NAME "/" ACME_CERT_KEY
#define ACME_DEV_EXAMPLE_DIR "../example"
#define ACME_DEV_FROM_CERT_PATH ACME_DEV_EXAMPLE_DIR "/cert.pem"
#define ACME_DEV_FROM_KEY_PATH ACME_DEV_EXAMPLE_DIR "/cert-key.pem"

/*
 * Function macros
 */
#define println_debug2(str, ngx_str, stream) \
    fwrite("ACME DEBUG: ", sizeof(char), strlen("ACME DEBUG: "), stream); \
    fwrite(str, sizeof(char), strlen(str), stream); \
    fwrite((ngx_str)->data, sizeof(char), (ngx_str)->len, stream); \
    fwrite("\n", sizeof(char), 1, stream); \
    fflush(stream)
#define println_debug(str, ngx_str) \
    println_debug2(str, ngx_str, stdout)

static char *ngx_http_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_acme_main(ngx_conf_t *cf, void *conf);
static char *ngx_http_acme_fetch_dir(ngx_conf_t *cf, void *conf, ngx_str_t *replay_nonce);
static char *ngx_http_acme_new_reg(ngx_conf_t *cf, void *conf, ngx_str_t *replay_nonce, RSA *key);
static char *ngx_http_acme_new_auth(ngx_conf_t *cf, void *conf, ngx_str_t *replay_nonce, RSA *key);
static char *ngx_http_acme_request(ngx_conf_t *cf, void *conf, char *url, ngx_http_acme_http_method_t http_method,
        json_t *request_json, RSA *key, ngx_str_t *replay_nonce, json_t **response_json,
        ngx_http_acme_slist_t **response_headers);
static char *ngx_http_acme_sign_json(ngx_conf_t *cf, void *conf, json_t *payload, RSA *key, ngx_str_t replay_nonce, json_t **flattened_jws);
static char *ngx_http_acme_create_jwk(ngx_conf_t *cf, void *conf, RSA *key, json_t **jwk);
//static char *ngx_http_acme_create_priv_jwk(ngx_conf_t *cf, void *conf, RSA *key, json_t **jwk);
static char *ngx_http_acme_read_jwk(ngx_conf_t *cf, void *conf, ngx_str_t jwk_str, RSA **key);
static char *ngx_http_acme_json_request(ngx_conf_t *cf, void *conf, char *url, ngx_http_acme_http_method_t http_method,
        json_t *request_json, json_t **response_json, ngx_http_acme_slist_t **response_headers);
static char *ngx_http_acme_plain_request(ngx_conf_t *cf, void *conf, char *url, ngx_http_acme_http_method_t http_method,
        ngx_str_t request_data, ngx_str_t *response_data, ngx_http_acme_slist_t **response_headers);
static size_t ngx_http_acme_header_callback(char *buffer, size_t size, size_t nitems, void *userdata);
static ngx_int_t ngx_http_acme_init(ngx_conf_t *cf);

//static ngx_http_acme_sdict_t *ngx_http_acme_sdict_append_kv_pair(ngx_http_acme_sdict_t *sdict, ngx_str_t key, ngx_str_t value);
//static void ngx_http_acme_sdict_free_all(ngx_http_acme_sdict_t *sdict);
static ngx_http_acme_slist_t *ngx_http_acme_slist_append_entry(ngx_http_acme_slist_t *slist, ngx_str_t value);
static void ngx_http_acme_slist_free_all(ngx_http_acme_slist_t *slist);


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

    // TODO (KK) Pull the different parts out as own methods for readability

    /*
     * TODO (KK) Get the config directory path (e.g. /etc/nginx)
     */


    /*
     * TODO (KK) Init acme dir (mkdirs)
     */


    /*
     * ACME communication - getting a certificate
     */

    if(ngx_http_acme_main(cf, conf) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error while gathering certificate from ACME server");
        return NGX_CONF_ERROR;
    }

    /*
     * TODO (KK) Install certificate (right now it just copies an example cert)
     */
    {
        ngx_copy_file_t   cpyf;

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Installing certificate and key");

        cpyf.size = -1;
        cpyf.buf_size = 0;
        cpyf.access =  NGX_FILE_DEFAULT_ACCESS;
        cpyf.time = -1;
        cpyf.log = cf->log;

        /* Copy certificate */
        ret = ngx_copy_file((u_char *)ACME_DEV_FROM_CERT_PATH, (u_char *)ACME_DEV_CERT_PATH, &cpyf);

        /* Copy private key */
        if(ret == NGX_OK) {
            /* Only 0600 access for private key */
            cpyf.access = NGX_FILE_OWNER_ACCESS;

            ret = ngx_copy_file((u_char *)ACME_DEV_FROM_KEY_PATH, (u_char *)ACME_DEV_KEY_PATH, &cpyf);
        }

        if(ret != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Installing the certificate or private key failed");
            return NGX_CONF_ERROR;
        }
    }

    /*
     * Fool the SSL module into using the ACME certificates
     */
    /* Get SSL module configuration */
    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

    // TODO (KK) Report warning when ssl configs are not set (acme w/o ssl activated in the same server context is an error)
    // --> Maybe ignore acme config then and issue a warning

    if(sscf) {
//        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Found SSL certificate path: %s", sscf->certificate.data);

        /* Spoof SSL cert */
        ngx_str_set(&sscf->certificate, ACME_DIR "/" ACME_LIVE_DIR "/" ACME_DEV_SERVER_NAME "/" ACME_CERT);
        ngx_str_set(&sscf->certificate_key, ACME_DIR "/" ACME_LIVE_DIR "/" ACME_DEV_SERVER_NAME "/" ACME_CERT_KEY);
    }


    return NGX_CONF_OK;
} /* ngx_http_acme */


static char *ngx_http_acme_main(ngx_conf_t *cf, void *conf)
{
    /*
     * Function's logic in pseudo code:
     *
     * if (certificate file exists) {
     *    if (cert is not expired) {
     *       return
     *    }
     * }
     *
     * if (no account key exists) {
     *    create account key
     * } else {
     *    load account key from file
     * }
     *
     * if (there is no registration for this account key on the ACME server) {
     *    register
     * }
     *
     * if (there is no authorization for this domain on this ACME account) {
     *    authorize and solve the challenges
     * }
     *
     * if (the certificate exists but is expired) {
     *    renew cert and return
     * }
     *
     * get the certificate from the server and return
     *
     */

    int ret;
    ngx_str_t replay_nonce = ngx_null_string;

    /*
     * Load key pair for ACME account
     */
    RSA *rsa = NULL;

    /* TODO (KK) Extract to own method */
    if(1 /* if no account key exists */)
    {
        /*
         * Generate new key pair
         */
        BIGNUM *e = NULL;

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Generate RSA key");

        // TODO (KK) Change key type to EVP_PKEY everywhere for being able to handle other keys than RSA
        rsa = RSA_new();
        ret = BN_dec2bn(&e, ACME_ACCOUNT_RSA_EXP);
        if(ret == 0) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                    "Error creating the account key. OpenSSL error 0x%xl", ERR_get_error());
            return NGX_CONF_ERROR;
        }

        ret = RSA_generate_key_ex(rsa, ACME_ACCOUNT_RSA_BITS, e, NULL);
        if(ret == 0) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                    "Error creating the account key. OpenSSL error 0x%xl", ERR_get_error());
            return NGX_CONF_ERROR;
        }

        // TODO (KK) Save account key in file
//        ngx_http_acme_create_priv_jwk(ngx_conf_t *cf, void *conf, RSA *key, json_t **jwk)

        BN_free(e);
    } else {
        /*
         * Load existing account key from file
         */
        // TODO (KK) Read JWK file to a string (and free it afterwards)

        if(ngx_http_acme_read_jwk(cf, conf, (ngx_str_t)ngx_null_string, &rsa) != NGX_CONF_OK) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to load the account key from file");
            return NGX_CONF_ERROR;
        }
    }


    /* Fetch ACME dir - just to retrieve a replay nonce */
    if(ngx_http_acme_fetch_dir(cf, conf, &replay_nonce) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to make directory request");
        return NGX_CONF_ERROR;
    }

    /* Register an account */
    if(ngx_http_acme_new_reg(cf, conf, &replay_nonce, rsa) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to register");
        return NGX_CONF_ERROR;
    }

    /* Authorize for domain */
    if(ngx_http_acme_new_auth(cf, conf, &replay_nonce, rsa) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to authorize");
        return NGX_CONF_ERROR;
    }



//    json_t *test_obj;
//    json_t *test_output;
//
//    /* TODO (KK) Test - remove later: Send request data */
//    test_obj = json_pack("{s:s}", "test", "Test string");
//    if(ngx_http_acme_json_request(cf, conf, "http://www.foaas.com/operations", GET, json_null(), &test_output, NULL) != NGX_CONF_OK) {
//        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "JSON request failed");
//        return NGX_CONF_ERROR;
//    }
//
//    char *output_str = json_dumps(test_output, 0);
//    println_debug("Returned JSON string: ", &((ngx_str_t)ngx_string_dynamic(output_str)));
//
//    json_decref(test_obj);
//    json_decref(test_output);
//
//    /* TODO (KK) Test - remove later: Sign off JSON */
//    test_obj = json_pack("{s:s}", "test", "Test string");
//    if(ngx_http_acme_sign_json(cf, conf, test_obj, rsa, replay_nonce, &test_output) != NGX_CONF_OK) {
//        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Creating JWS failed");
//        return NGX_CONF_ERROR;
//    }
//
//    output_str = json_dumps(test_output, 0);
//    println_debug("JWS string: ", &((ngx_str_t)ngx_string_dynamic(output_str)));
//
//    json_decref(test_obj);
//    json_decref(test_output);
//    ngx_free(output_str);


    RSA_free(rsa);

    return NGX_CONF_OK;
} /* ngx_http_acme_main */


static char *ngx_http_acme_fetch_dir(ngx_conf_t *cf, void *conf, ngx_str_t *replay_nonce)
{
    json_t *response_json;
    ngx_http_acme_slist_t *response_headers = NULL;

    /* Make JSON request */
    if(ngx_http_acme_request(cf, conf, ACME_SERVER "/directory", GET, json_null(), NULL, replay_nonce, &response_json, &response_headers) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error while making JSON request");
        return NGX_CONF_ERROR;
    }

    ngx_http_acme_slist_free_all(response_headers);
    json_decref(response_json);

    return NGX_CONF_OK;
} /* ngx_http_acme_fetch_dir */


static char *ngx_http_acme_new_reg(ngx_conf_t *cf, void *conf, ngx_str_t *replay_nonce, RSA *key)
{
    json_t *request_json;
    json_t *response_json;
    ngx_http_acme_slist_t *response_headers = NULL;
    ngx_http_acme_slist_t *response_headers2 = NULL;
    ngx_http_acme_slist_t *header = NULL;
    ngx_str_t tos_url = ngx_null_string;
    char *reg_location = NULL;
    size_t reg_location_len = 0;
    char *tmp, *max_addr, *min_addr;

    /* Assemble request */
    request_json = json_pack("{s:s}", "resource", "new-reg");

    /* Make JSON request */
    if(ngx_http_acme_request(cf, conf, ACME_SERVER "/acme/new-reg", POST, request_json, key, replay_nonce, &response_json, &response_headers) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error while making JSON request");
        return NGX_CONF_ERROR;
    }

    /* Process response */

    /* Search for and extract the location of the registration object */
    for(header = response_headers; header != NULL; header = header->next) {
        if(header->value_len < strlen(ACME_LOCATION_HEADER_PREFIX_STRING))
            continue;

        if(ngx_strncmp(header->value, ACME_LOCATION_HEADER_PREFIX_STRING, strlen(ACME_LOCATION_HEADER_PREFIX_STRING)) == 0) {
            /* Location header found, extract it */
            reg_location_len = header->value_len - strlen(ACME_LOCATION_HEADER_PREFIX_STRING) + 1 /* for terminating null character */;
            reg_location = ngx_alloc(reg_location_len, cf->log);
            ngx_memcpy(reg_location, header->value + strlen(ACME_LOCATION_HEADER_PREFIX_STRING), reg_location_len - 1);
            reg_location[reg_location_len - 1] = '\0';
            break;
        }
    }

    if(header == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Location of registration object not found in HTTP response headers");
        return NGX_CONF_ERROR;
    }

    /*
     * Terms of service agreement
     */

    /* Search for and extract terms-of-service url from response headers */
    for(header = response_headers; header != NULL; header = header->next) {
        /* Check minimum length */
        if(header->value_len < strlen(ACME_TOS_PREFIX_STRING ACME_TOS_SUFFIX_STRING))
            continue;

        /* Check prefix */
        if(ngx_strncmp(header->value, ACME_TOS_PREFIX_STRING, strlen(ACME_TOS_PREFIX_STRING)) != 0)
            continue;

        /* Search backwards */
        min_addr = header->value + strlen(ACME_TOS_PREFIX_STRING);
        max_addr = header->value + header->value_len - strlen(ACME_TOS_SUFFIX_STRING);
        for(tmp = max_addr; tmp >= min_addr; tmp--) {
           if(ngx_strncmp(tmp, ACME_TOS_SUFFIX_STRING, strlen(ACME_TOS_SUFFIX_STRING)) == 0) {
               goto found;
           }
        }
    }

    /* No terms-of-service link found, so we don't need to agree to anything */
    goto new_reg_end;

    found:
    tos_url.data = (u_char *) min_addr;
    tos_url.len = tmp - min_addr;

    /* Send a registration update to agree to the TOS */

    /* Free local variables before reusing them */
    json_decref(request_json);
    json_decref(response_json);

    /* Assemble request */
    request_json = json_pack("{s:s,s:s%}", "resource", "reg", "agreement", tos_url.data, tos_url.len);

    /* Make JSON request */
    if(ngx_http_acme_request(cf, conf, reg_location, POST, request_json, key, replay_nonce, &response_json, &response_headers2) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error while making JSON request");
        return NGX_CONF_ERROR;
    }
    ngx_http_acme_slist_free_all(response_headers2);

    new_reg_end:
    ngx_free(reg_location);
    json_decref(request_json);
    json_decref(response_json);
    ngx_http_acme_slist_free_all(response_headers);

    return NGX_CONF_OK;
} /* ngx_http_acme_new_reg */


static char *ngx_http_acme_new_auth(ngx_conf_t *cf, void *conf, ngx_str_t *replay_nonce, RSA *key)
{
    json_t *request_json;
    json_t *response_json;
    ngx_http_acme_slist_t *response_headers = NULL;

    /* Assemble request */
    request_json = json_pack("{s:s, s:{s:s, s:s} }", "resource", "new-authz",
            "identifier", "type", "dns", "value", ACME_DEV_SERVER_NAME);

    /* Make JSON request */
    if(ngx_http_acme_request(cf, conf, ACME_SERVER "/acme/new-authz", POST, request_json, key, replay_nonce, &response_json, &response_headers) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error while making JSON request");
        return NGX_CONF_ERROR;
    }

    /* Process response */



    json_decref(request_json);
    json_decref(response_json);
    ngx_http_acme_slist_free_all(response_headers);

    return NGX_CONF_OK;
} /* ngx_http_acme_new_auth */


static char *ngx_http_acme_request(ngx_conf_t *cf, void *conf, char *url, ngx_http_acme_http_method_t http_method,
        json_t *request_json, RSA *key, ngx_str_t *replay_nonce, json_t **response_json,
        ngx_http_acme_slist_t **response_headers)
{
    json_t *signed_request_json;
    ngx_http_acme_slist_t *header = NULL;

    /* Sign JSON and create JWS from the request JSON data */
    if(json_is_null(request_json)) {
        signed_request_json = json_null();
    } else {
        if(ngx_http_acme_sign_json(cf, conf, request_json, key, *replay_nonce, &signed_request_json) != NGX_CONF_OK) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Creating JWS failed");
            return NGX_CONF_ERROR;
        }
    }

    /* Make JSON request */
    if(ngx_http_acme_json_request(cf, conf, url, http_method, signed_request_json, response_json, response_headers) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error while making JSON request");
        return NGX_CONF_ERROR;
    }

    if(replay_nonce->data != NULL)
        ngx_free(replay_nonce->data);
    ngx_str_null(replay_nonce);
    json_decref(signed_request_json);

    /* Search for and extract replay nonce from response headers */
    for(header = *response_headers; header != NULL; header = header->next) {
        if(header->value_len < strlen(ACME_REPLAY_NONCE_PREFIX_STRING))
            continue;

        if(ngx_strncmp(header->value, ACME_REPLAY_NONCE_PREFIX_STRING, strlen(ACME_REPLAY_NONCE_PREFIX_STRING)) == 0) {
            /* Replay nonce found, extract it */
            replay_nonce->len = header->value_len - strlen(ACME_REPLAY_NONCE_PREFIX_STRING);
            replay_nonce->data = ngx_alloc(replay_nonce->len, cf->log);
            ngx_memcpy(replay_nonce->data, header->value + strlen(ACME_REPLAY_NONCE_PREFIX_STRING), replay_nonce->len);
            break;
        }
    }

    if(header == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "No Replay-Nonce found in HTTP response headers");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
} /* ngx_http_acme_create_jwk */

static char *ngx_http_acme_sign_json(ngx_conf_t *cf, void *conf, json_t *payload, RSA *key, ngx_str_t replay_nonce, json_t **flattened_jws)
{
    /*
     * Structure according to RFC7515:
     *
     * {
     *  "payload":"<payload contents>",
     *  "protected":"<integrity-protected header contents>",
     *  "header":<non-integrity-protected header contents>,
     *  "signature":"<signature contents>"
     * }
     *
     * Example:
     *
     * {
     *  "payload":
     *   "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
     *  "protected":"eyJhbGciOiJFUzI1NiJ9",
     *  "header": {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
     *  "signature":
     *   "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
     * }
     */

    /*
     * ACME restrictions:
     * The JWS MUST use the Flattened JSON Serialization
     * The JWS MUST be encoded using UTF-8
     * The JWS Header or Protected Header MUST include “alg” and “jwk” fields
     * The JWS MUST NOT have the value “none” in its “alg” field
     */

    json_t *jwk;
    json_t *header;
    ngx_str_t encoded_protected_header, serialized_payload, encoded_payload, tmp;
    ngx_str_t signing_input, signature, encoded_signature;
    u_char *tmp_char_p;

    /* Variables for signing */
    EVP_PKEY *evp_key;
    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;

    /*
     * Encode payload
     */

    serialized_payload = (ngx_str_t)ngx_string_dynamic(json_dumps(payload, 0));
    encoded_payload.len = ngx_base64_encoded_length(serialized_payload.len);
    encoded_payload.data = ngx_alloc(encoded_payload.len, cf->log);
    ngx_encode_base64url(&encoded_payload, &serialized_payload);

    println_debug("Signing payload: ", &serialized_payload);

    /*
     * Create header
     */

    /* jwk header */
    if(ngx_http_acme_create_jwk(cf, conf, key, &jwk) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to create the JWK from the account key");
        ngx_free(serialized_payload.data);
        ngx_free(encoded_payload.data);
        return NGX_CONF_ERROR;
    }

    /* Pack header into JSON */
    header = json_pack("{s:s, s:s%, s:o}", "alg", "RS256", "nonce", replay_nonce.data, replay_nonce.len, "jwk", jwk);
    if(header == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error packing JWS header");
        ngx_free(serialized_payload.data);
        ngx_free(encoded_payload.data);
        return NGX_CONF_ERROR;
    }

    /* Serialize and base64url encode header */
    tmp = (ngx_str_t)ngx_string_dynamic(json_dumps(header, 0));
    encoded_protected_header.len = ngx_base64_encoded_length(tmp.len);
    encoded_protected_header.data = ngx_alloc(encoded_protected_header.len, cf->log);
    ngx_encode_base64url(&encoded_protected_header, &tmp);
    ngx_free(tmp.data);
    json_decref(header);

    /*
     * Create signature
     */

    /* Create signing input */
    /* = ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)) */
    signing_input.len = encoded_protected_header.len + strlen(".") + encoded_payload.len;
    signing_input.data = ngx_alloc(signing_input.len, cf->log);
    tmp_char_p = ngx_copy(signing_input.data, encoded_protected_header.data, encoded_protected_header.len);
    tmp_char_p = ngx_copy(tmp_char_p, ".", strlen("."));
    tmp_char_p = ngx_copy(tmp_char_p, encoded_payload.data, encoded_payload.len);

    /* Convert the RSA key to the EVP_PKEY structure */
    evp_key = EVP_PKEY_new();
    if(evp_key == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                "Error signing the message digest for the JWS signature.");
        return NGX_CONF_ERROR;
    }

    if(EVP_PKEY_set1_RSA(evp_key, key) == 0) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                "Error signing the message digest for the JWS signature.");
        return NGX_CONF_ERROR;
    }

    /* Create the message digest context */
    ret = 0;
    mdctx = EVP_MD_CTX_create();
    if(mdctx == NULL)
        goto err;

    /* Initialize the DigestSign operation - SHA-256 has been selected as the message digest function */
    if(EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, evp_key) != 1)
        goto err;

    /* Call update with the message */
    if(EVP_DigestSignUpdate(mdctx, signing_input.data, signing_input.len) != 1)
        goto err;

    /* Finalise the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the */
    /* signature. The length is returned in siglen. */
    if(EVP_DigestSignFinal(mdctx, NULL, &signature.len) != 1)
        goto err;

    /* Allocate memory for the signature */
    signature.data = ngx_alloc(signature.len, cf->log);

    /* Obtain the signature */
    if(EVP_DigestSignFinal(mdctx, signature.data, &signature.len) != 1)
        goto err;

    /* Success */
    ret = 1;

    err:
    if(ret != 1) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                "Error signing the message digest for the JWS signature. OpenSSL error 0x%xl", ERR_get_error());
        return NGX_CONF_ERROR;
    }

    /* Clean up */
    EVP_MD_CTX_destroy(mdctx);
    EVP_PKEY_free(evp_key);

    /* base64url encode the signature */
    encoded_signature.len = ngx_base64_encoded_length(signature.len);
    encoded_signature.data = ngx_alloc(encoded_signature.len, cf->log);
    ngx_encode_base64url(&encoded_signature, &signature);
    ngx_free(signature.data);

    /*
     * Create flattened JWS serialization
     */

    *flattened_jws = json_pack("{s:s%,s:s%,s:s%}",
            "payload", encoded_payload.data, encoded_payload.len,
            "protected", encoded_protected_header.data, encoded_protected_header.len,
            "signature", encoded_signature.data, encoded_signature.len
            );

    ngx_free(serialized_payload.data);
    // TODO (KK) Maybe this is too early for a free since the strings will be used in the flattened JWS (but when to free then?)
    ngx_free(encoded_payload.data);
    ngx_free(encoded_protected_header.data);
    ngx_free(encoded_signature.data);

    if(*flattened_jws == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error serializing flattened JWS");
        return NGX_CONF_ERROR;
    }


    return NGX_CONF_OK;
} /* ngx_http_acme_sign_json */


static char *ngx_http_acme_create_jwk(ngx_conf_t *cf, void *conf, RSA *key, json_t **jwk)
{
    ngx_str_t e, n, tmp;

    /* Baser64url encode e */
    tmp.len = BN_num_bytes(key->e);
    tmp.data = ngx_alloc(tmp.len, cf->log);
    tmp.len = BN_bn2bin(key->e, tmp.data);
    e.len = ngx_base64_encoded_length(tmp.len);
    e.data = ngx_alloc(e.len, cf->log);
    ngx_encode_base64url(&e, &tmp);
    ngx_free(tmp.data);

    /* Baser64url encode n */
    tmp.len = BN_num_bytes(key->n);
    tmp.data = ngx_alloc(tmp.len, cf->log);
    tmp.len = BN_bn2bin(key->n, tmp.data);
    n.len = ngx_base64_encoded_length(tmp.len);
    n.data = ngx_alloc(n.len, cf->log);
    ngx_encode_base64url(&n, &tmp);
    ngx_free(tmp.data);

    *jwk = json_pack("{s:s, s:s%, s:s%}", "kty", "RSA", "e", e.data, e.len, "n", n.data, n.len);
    if(*jwk == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to pack JWK");
        return NGX_CONF_ERROR;
    }

    ngx_free(e.data);
    ngx_free(n.data);

    return NGX_CONF_OK;
} /* ngx_http_acme_create_jwk */

//static char *ngx_http_acme_create_priv_jwk(ngx_conf_t *cf, void *conf, RSA *key, json_t **jwk)
//{
//    // TODO (KK) Create JWK with following information
//    // d, e, n, q, p, qi, dp, dq
//    // kty: RSA
//
//    return NGX_CONF_OK;
//} /* ngx_http_acme_create_priv_jwk */

static char *ngx_http_acme_read_jwk(ngx_conf_t *cf, void *conf, ngx_str_t jwk_str, RSA **key)
{
    json_t *jwk;
    json_error_t error;

    /*
     * Deserialize JWK
     */
    jwk = json_loadb((char *) jwk_str.data, jwk_str.len, 0, &error);
    free(jwk_str.data);
    ngx_str_null(&jwk_str);

    if(jwk == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                "Error parsing JSON: on line %d: %s\n", error.line, error.text);
        return NGX_CONF_ERROR;
    }

    // TODO (KK) Form RSA struct from JWK

    return NGX_CONF_OK;
} /* ngx_http_acme_create_jwk */

static char *ngx_http_acme_json_request(ngx_conf_t *cf, void *conf, char *url, ngx_http_acme_http_method_t http_method,
        json_t *request_json, json_t **response_json, ngx_http_acme_slist_t **response_headers)
{
    ngx_str_t response_data;
    ngx_str_t request_data;
    char *tmp;

    json_error_t error;

    /* Convert request_json to string to provide it to the following method */
    request_data = (ngx_str_t)ngx_null_string;
    if(!json_is_null(request_json)) {
        tmp = json_dumps(request_json, 0);
        if(tmp == NULL) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error while creating request string from JSON\n");
            return NGX_CONF_ERROR;
        } else {
            request_data.data = (u_char *)tmp;
            request_data.len = ngx_strlen(tmp);
        }
    }

    /* Make request */
    if(ngx_http_acme_plain_request(cf, conf, url, http_method, request_data, &response_data, response_headers) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error while making request\n");
        return NGX_CONF_ERROR;
    }

    /* Now all the returned JSON is in the data variable */

    /*
     * Parsing returned JSON
     */

    /* Begin Jansson part */

    if(response_data.len <= 0) {
        *response_json = json_null();
    } else {
        *response_json = json_loadb((char *) response_data.data, response_data.len, 0, &error);
    }
    free(response_data.data);
    ngx_str_null(&response_data);

    if(*response_json == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                "Error parsing JSON: on line %d: %s\n", error.line, error.text);
        return NGX_CONF_ERROR;
    }

    /* End Jansson part */

    return NGX_CONF_OK;
} /* ngx_http_acme_json_request */

static char *ngx_http_acme_plain_request(ngx_conf_t *cf, void *conf, char *url, ngx_http_acme_http_method_t http_method,
        ngx_str_t request_data, ngx_str_t *response_data, ngx_http_acme_slist_t **response_headers)
{
    CURL *curl;
    CURLcode res;
    struct curl_slist *request_headers = NULL;

    FILE *response_data_stream;

    /* Begin cURL part */

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();

    if(curl == NULL)
        return NGX_CONF_ERROR;

    curl_easy_setopt(curl, CURLOPT_URL, url);

    /*
     * Setting the HTTP method
     */

    if(http_method == GET) {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    } else if(http_method == POST) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
    }

    /*
     * Setting the request data handling
     */

    if(request_data.data != NULL) {

        // TODO (KK) Add method parameter for the header list to be dynamic in e.g. the content type, since it doesn't always have to be JSON ;)
        request_headers = curl_slist_append(request_headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request_headers);

        /* size of the data to copy from the buffer and send in the request */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request_data.len);

        /* send data from the local stack */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_data.data);

        println_debug("Request data: ", &request_data);
    }

    /*
     * Setting the response data handling
     */

    /* Setup the stream for the response data */
    response_data_stream = open_memstream((char **) &response_data->data, &response_data->len);

    if(response_data_stream == NULL) {
        curl_slist_free_all(request_headers);
        curl_easy_cleanup(curl);
        return NGX_CONF_ERROR;
    }

    /*
     * ATTENTION: Setting CURLOPT_WRITEDATA without CURLOPT_WRITEFUNCTION does not work on Windows
     * according to https://curl.haxx.se/libcurl/c/CURLOPT_WRITEDATA.html
     */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_data_stream);

    /*
     * Setting the response header handling
     */

    if (response_headers != NULL) {
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, response_headers);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION,
                ngx_http_acme_header_callback);
    }

    /*
     * Perform the request
     */

    res = curl_easy_perform(curl);

    /* Check for errors */
    if(res != CURLE_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                "Error while performing request: %s\n", curl_easy_strerror(res));
        fclose(response_data_stream);
        curl_slist_free_all(request_headers);
        curl_easy_cleanup(curl);
        return NGX_CONF_ERROR;
    }

    /* always cleanup */
    curl_easy_cleanup(curl);

    fclose(response_data_stream);

    /* free the custom headers */
    curl_slist_free_all(request_headers);

    /* End cURL part */

    println_debug("Response data: ", response_data);

    return NGX_CONF_OK;
} /* ngx_http_acme_plain_request */

static size_t ngx_http_acme_header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
    ngx_http_acme_slist_t **slist = (ngx_http_acme_slist_t **) userdata;
    ngx_str_t entry;

    if(size * nitems <= 0)
        return 0;

    /* Subtract 2 from the length to trim off the \r\n */
    entry.len = (size * nitems) - 2;
    entry.data = (u_char *) buffer;

    *slist = ngx_http_acme_slist_append_entry(*slist, entry);
    if(*slist == NULL)
        return 0;

    return nitems * size;
} /* ngx_http_acme_header_callback */

/**
 * TODO (KK) delete
 * This entry point is too late, we will probably never use it.
 */
static ngx_int_t ngx_http_acme_init(ngx_conf_t *cf)
{
    return NGX_OK;
} /* ngx_http_acme_init */

/*
 * Utility functions
 */

/* Dictionary functions */
//static ngx_http_acme_sdict_t *ngx_http_acme_sdict_append_kv_pair(ngx_http_acme_sdict_t *sdict, ngx_str_t key, ngx_str_t value)
//{
//    ngx_http_acme_sdict_t *new_sdict, *last;
//
//    if(sdict != NULL)
//        for(last = sdict; last->next != NULL; last = last->next);
//
//    new_sdict = malloc(sizeof(ngx_http_acme_sdict_t));
//
//    if(new_sdict == NULL) {
//        fprintf(stderr, "Error while allocating new memory for the new dictionary entry");
//        return NULL;
//    }
//
//    // Fill out new entry
//    new_sdict->key = (char *) key.data;
//    new_sdict->key_len = key.len;
//    new_sdict->value = (char *) value.data;
//    new_sdict->value_len = value.len;
//    new_sdict->next = NULL;
//
//    // Add new entry to the list
//    if(sdict == NULL) {
//        sdict = new_sdict;
//    } else {
//        last->next = new_sdict;
//    }
//
//    return sdict;
//} /* ngx_http_acme_sdict_append_kv_pair */
//
//static void ngx_http_acme_sdict_free_all(ngx_http_acme_sdict_t *sdict)
//{
//    ngx_http_acme_sdict_t *tmp;
//
//    while(sdict != NULL) {
//        tmp = sdict->next;
//        free(sdict);
//        sdict = tmp;
//    }
//} /* ngx_http_acme_sdict_free_all */


/* List functions */
static ngx_http_acme_slist_t *ngx_http_acme_slist_append_entry(ngx_http_acme_slist_t *slist, ngx_str_t value)
{
    ngx_http_acme_slist_t *new_slist, *last;

    if(slist != NULL)
        for(last = slist; last->next != NULL; last = last->next);

    new_slist = malloc(sizeof(ngx_http_acme_slist_t));

    if(new_slist == NULL) {
        fprintf(stderr, "Error while allocating new memory for the new list entry");
        return NULL;
    }

    /* Copy new entry */
    new_slist->value_len = value.len;
    new_slist->next = NULL;

    new_slist->value = malloc(new_slist->value_len);
    ngx_memcpy(new_slist->value, value.data, new_slist->value_len);

    /* Add new entry to the list */
    if(slist == NULL) {
        slist = new_slist;
    } else {
        last->next = new_slist;
    }

    return slist;
} /* ngx_http_acme_slist_append_entry */

static void ngx_http_acme_slist_free_all(ngx_http_acme_slist_t *slist)
{
    ngx_http_acme_slist_t *tmp;

    while(slist != NULL) {
        tmp = slist->next;
        free(slist->value);
        free(slist);
        slist = tmp;
    }
} /* ngx_http_acme_slist_free_all */

