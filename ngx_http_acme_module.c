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
 * Temporary dev macros
 */
// Nginx config directory; This should later be gathered from nginx
#define ACME_DEV_CONF_DIR "conf"
// This should later be replaced with the value of the server_name directive of the core module
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
static char *ngx_http_acme_fetch_dir(ngx_conf_t *cf, void *conf);
static char *ngx_http_acme_sign_json(ngx_conf_t *cf, void *conf, json_t *payload, RSA *key, json_t **flattened_jws);
static char *ngx_http_acme_create_jwk(ngx_conf_t *cf, void *conf, RSA *key, json_t **jwk);
static char *ngx_http_acme_read_jwk(ngx_conf_t *cf, void *conf, ngx_str_t jwk_str, RSA **key);
static char *ngx_http_acme_json_request(ngx_conf_t *cf, void *conf, char *url, ngx_http_acme_http_method_t http_method, json_t *request_json, json_t **response_json);
static char *ngx_http_acme_plain_request(ngx_conf_t *cf, void *conf, char *url, ngx_http_acme_http_method_t http_method, ngx_str_t request_data, ngx_str_t *response_data);
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

    // TODO (KK) Pull the different parts out as own methods for readability

    /*
     * TODO (KK) Get the config directory path (e.g. /etc/nginx)
     */


    /*
     * TODO (KK) Init acme dir (mkdirs)
     */

    /*
     * TODO (KK) ACME stuff
     */
    ngx_http_acme_main(cf, conf);

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

        // Copy certificate
        ret = ngx_copy_file((u_char *)ACME_DEV_FROM_CERT_PATH, (u_char *)ACME_DEV_CERT_PATH, &cpyf);

        // Copy private key
        if(ret == NGX_OK) {
            // Only 0600 access for private key
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

        rsa = RSA_new();
        ret = BN_dec2bn(&e, ACME_ACCOUNT_RSA_EXP);
        if(ret == 0) {
            // TODO (KK) Report error
        }

        ret = RSA_generate_key_ex(rsa, ACME_ACCOUNT_RSA_BITS, e, NULL);
        if(ret == 0) {
            // TODO (KK) Report error
        }

        // TODO (KK) Save account key in file

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


    /* TODO (KK) Test - remove later: Fetch ACME dir */
    if(ngx_http_acme_fetch_dir(cf, conf) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to make directory request");
        return NGX_CONF_ERROR;
    }


    json_t *test_obj;
    json_t *test_output;

    /* TODO (KK) Test - remove later: Send request data */
    test_obj = json_pack("{s:s}", "test", "Test string");
    if(ngx_http_acme_json_request(cf, conf, "http://www.foaas.com/operations", GET, json_null(), &test_output) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "JSON request failed");
        return NGX_CONF_ERROR;
    }

    char *output_str = json_dumps(test_output, 0);
    println_debug("Returned JSON string: ", &((ngx_str_t)ngx_string_dynamic(output_str)));

    json_decref(test_obj);
    json_decref(test_output);

    /* TODO (KK) Test - remove later: Sign off JSON */
    test_obj = json_pack("{s:s}", "test", "Test string");
    if(ngx_http_acme_sign_json(cf, conf, test_obj, rsa, &test_output) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Creating JWS failed");
        return NGX_CONF_ERROR;
    }

    output_str = json_dumps(test_output, 0);
    println_debug("JWS string: ", &((ngx_str_t)ngx_string_dynamic(output_str)));

    json_decref(test_obj);
    json_decref(test_output);
    ngx_free(output_str);


    RSA_free(rsa);

    return NGX_CONF_OK;
} /* ngx_http_acme_main */


static char *ngx_http_acme_fetch_dir(ngx_conf_t *cf, void *conf)
{
    json_t *root_object;
//    json_error_t error;

    /* Make JSON request */
    if(ngx_http_acme_json_request(cf, conf, ACME_SERVER "/directory", GET, json_null(), &root_object) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error while making JSON request");
        return NGX_CONF_ERROR;
    }

    /* The part below is different for each ACME request */

    // TODO (KK) extract the JSON to a custom data type

    json_decref(root_object);

    return NGX_CONF_OK;
} /* ngx_http_acme_fetch_dir */


static char *ngx_http_acme_sign_json(ngx_conf_t *cf, void *conf, json_t *payload, RSA *key, json_t **flattened_jws)
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
    ngx_str_t protected_header, serialized_payload, encoded_payload, tmp;

    /*
     * Encode payload
     */

    serialized_payload = (ngx_str_t)ngx_string_dynamic(json_dumps(payload, 0));
    encoded_payload.len = serialized_payload.len;
    encoded_payload.data = ngx_alloc(ngx_base64_encoded_length(encoded_payload.len), cf->log);
    ngx_encode_base64url(&encoded_payload, &serialized_payload);

    /*
     * Create header
     */

    // jwk header
    if(ngx_http_acme_create_jwk(cf, conf, key, &jwk) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to create the JWK from the account key");
        return NGX_CONF_ERROR;
    }

    // TODO (KK) nonce header

    // Pack header into JSON
    // TODO (KK) add alg header
    header = json_pack("{s:s, s:s, s:o}", "alg", "", "nonce", "", "jwk", jwk);
    if(header == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error packing JWS header");
        return NGX_CONF_ERROR;
    }

    // Serialize and base64url encode header
    tmp = (ngx_str_t)ngx_string_dynamic(json_dumps(header, 0));
    protected_header.len = tmp.len;
    protected_header.data = ngx_alloc(ngx_base64_encoded_length(protected_header.len), cf->log);
    ngx_encode_base64url(&protected_header, &tmp);
    ngx_free(tmp.data);
    json_decref(header);

    /*
     * TODO (KK) Create signature
     */



    /*
     * Create flattened JWS serialization
     */
    *flattened_jws = json_pack("{s:s%,s:s%,s:s%}",
            "payload", encoded_payload.data, encoded_payload.len,
            "protected", protected_header.data, protected_header.len,
            "signature", "test", 4
            );
    if(*flattened_jws == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error serializing flattened JWS");
        return NGX_CONF_ERROR;
    }

    ngx_free(protected_header.data);
    ngx_free(serialized_payload.data);
    ngx_free(encoded_payload.data);

    return NGX_CONF_OK;
} /* ngx_http_acme_sign_json */


static char *ngx_http_acme_create_jwk(ngx_conf_t *cf, void *conf, RSA *key, json_t **jwk)
{
    ngx_str_t e, n, tmp;

    // Baser64url encode e
    tmp.len = BN_num_bytes(key->e);
    tmp.data = ngx_alloc(tmp.len, cf->log);
    tmp.len = BN_bn2bin(key->e, tmp.data);
    e.len = tmp.len;
    e.data = ngx_alloc(ngx_base64_encoded_length(e.len), cf->log);
    ngx_encode_base64url(&e, &tmp);
    ngx_free(tmp.data);

    // Baser64url encode n
    tmp.len = BN_num_bytes(key->n);
    tmp.data = ngx_alloc(tmp.len, cf->log);
    tmp.len = BN_bn2bin(key->n, tmp.data);
    n.len = tmp.len;
    n.data = ngx_alloc(ngx_base64_encoded_length(n.len), cf->log);
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

//static char *ngx_http_acme_base64url_encode(ngx_conf_t *cf, void *conf, ngx_str_t input, ngx_str_t *output)
//{
//
//    return NGX_CONF_OK;
//} /* ngx_http_acme_base64url_encode */

static char *ngx_http_acme_json_request(ngx_conf_t *cf, void *conf, char *url, ngx_http_acme_http_method_t http_method, json_t *request_json, json_t **response_json)
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
    if(ngx_http_acme_plain_request(cf, conf, url, http_method, request_data, &response_data) != NGX_CONF_OK) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Error while making request\n");
        return NGX_CONF_ERROR;
    }

    /* Now all the returned JSON is in the data variable */

    /*
     * Parsing returned JSON
     */

    /* Begin Jansson part */

    *response_json = json_loadb((char *) response_data.data, response_data.len, 0, &error);
    free(response_data.data);
    ngx_str_null(&response_data);

    if(*response_json == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                "Error parsing JSON: on line %d: %s\n", error.line, error.text);
        return NGX_CONF_ERROR;
    }

    /* The part below is different for each ACME request */

//    if(!json_is_object(*response_json)) {
//        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
//                "Error parsing JSON: received data is not a JSON object\n");
//        json_decref(*response_json);
//        return NGX_CONF_ERROR;
//    }

    /* End Jansson part */

    return NGX_CONF_OK;
} /* ngx_http_acme_json_request */


static char *ngx_http_acme_plain_request(ngx_conf_t *cf, void *conf, char *url, ngx_http_acme_http_method_t http_method, ngx_str_t request_data, ngx_str_t *response_data)
{
    CURL *curl;
    CURLcode res;
    struct curl_slist *header_list = NULL;

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
        header_list = curl_slist_append(header_list, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);

        /* size of the data to copy from the buffer and send in the request */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request_data.len);

        /* send data from the local stack */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_data.data);

        println_debug("Request data: ", &request_data);
    }

    /*
     * Setting the response data handling
     */

    /* Setup the stream for the reponse data */
    response_data_stream = open_memstream((char **) &response_data->data, &response_data->len);

    if(response_data_stream == NULL) {
        curl_easy_cleanup(curl);
        return NGX_CONF_ERROR;
    }

    /*
     * ATTENTION: Setting CURLOPT_WRITEDATA without CURLOPT_WRITEFUNCTION does not work on Windows
     * according to https://curl.haxx.se/libcurl/c/CURLOPT_WRITEDATA.html
     */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_data_stream);

    /*
     * Perform the request
     */

    res = curl_easy_perform(curl);

    /* Check for errors */
    if(res != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);

    fclose(response_data_stream);

    /* End cURL part */

    println_debug("Response data: ", response_data);

    return NGX_CONF_OK;
} /* ngx_http_acme_plain_request */

/**
 * TODO (KK) delete
 * This entry point is too late, we will probably never use it.
 */
static ngx_int_t ngx_http_acme_init(ngx_conf_t *cf)
{
    return NGX_OK;
} /* ngx_http_acme_init */
