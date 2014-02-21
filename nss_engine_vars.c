/* Copyright 2001-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mod_nss.h"
#include "secder.h"     /* DER_GetInteger() */
#include "base64.h"     /* BTOA_DataToAscii() */
#include "cert.h"       /* CERT_* */

/*  _________________________________________________________________
**
**  Variable Lookup
**  _________________________________________________________________
*/

#define CERT_NOTBEFORE 0
#define CERT_NOTAFTER  1

static char *nss_var_lookup_header(apr_pool_t *p, request_rec *r, const char *name);
static char *nss_var_lookup_ssl(apr_pool_t *p, conn_rec *c, char *var);
static char *nss_var_lookup_nss_cert(apr_pool_t *p, CERTCertificate *xs, char *var, conn_rec *c);
static char *nss_var_lookup_nss_cert_dn(apr_pool_t *p, CERTName *cert, char *var);
static char *nss_var_lookup_nss_cert_valid(apr_pool_t *p, CERTCertificate *xs, int type);
static char *ssl_var_lookup_ssl_cert_remain(apr_pool_t *p, CERTCertificate *xs);
static char *nss_var_lookup_nss_cert_chain(apr_pool_t *p, CERTCertificate *cert,char *var);
static char *nss_var_lookup_nss_cert_PEM(apr_pool_t *p, CERTCertificate *xs);
static char *nss_var_lookup_nss_cert_verify(apr_pool_t *p, conn_rec *c);
static char *nss_var_lookup_nss_cipher(apr_pool_t *p, conn_rec *c, char *var);
static char *nss_var_lookup_nss_version(apr_pool_t *p, char *var);
static char *nss_var_lookup_protocol_version(apr_pool_t *p, conn_rec *c);
static char *ssl_var_lookup(apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, char *var);

static APR_OPTIONAL_FN_TYPE(ssl_is_https) *othermod_is_https;
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *othermod_var_lookup;

static int nss_is_https(conn_rec *c)
{
    SSLConnRec *sslconn = myConnConfig(c);

    return (sslconn && sslconn->ssl)
        || (othermod_is_https && othermod_is_https(c));
}

static int ssl_is_https(conn_rec *c) {
    return nss_is_https(c);
}

void nss_var_register(void)
{
    /* Always register these mod_nss optional functions */
    APR_REGISTER_OPTIONAL_FN(nss_is_https);
    APR_REGISTER_OPTIONAL_FN(nss_var_lookup);

    /* Save the state of any previously registered mod_ssl functions */
    othermod_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
    othermod_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);

    /* Always register these local mod_ssl optional functions */
    APR_REGISTER_OPTIONAL_FN(ssl_is_https);
    APR_REGISTER_OPTIONAL_FN(ssl_var_lookup);

    return;
}

/* This function must remain safe to use for a non-SSL connection. */
char *nss_var_lookup(apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, char *var)
{
    SSLModConfigRec *mc = myModConfig(s);
    char *result;
    BOOL resdup;
    apr_time_exp_t tm;

    result = NULL;
    resdup = TRUE;

    /*
     * When no pool is given try to find one
     */
    if (p == NULL) {
        if (r != NULL)
            p = r->pool;
        else if (c != NULL)
            p = c->pool;
        else
            p = mc->pPool;
    }

    /*
     * Request dependent stuff
     */
    if (r != NULL) {
        switch (var[0]) {
        case 'H':
        case 'h':
            if (strcEQ(var, "HTTP_USER_AGENT"))
                result = nss_var_lookup_header(p, r, "User-Agent");
            else if (strcEQ(var, "HTTP_REFERER"))
                result = nss_var_lookup_header(p, r, "Referer");
            else if (strcEQ(var, "HTTP_COOKIE"))
                result = nss_var_lookup_header(p, r, "Cookie");
            else if (strcEQ(var, "HTTP_FORWARDED"))
                result = nss_var_lookup_header(p, r, "Forwarded");
            else if (strcEQ(var, "HTTP_HOST"))
                result = nss_var_lookup_header(p, r, "Host");
            else if (strcEQ(var, "HTTP_PROXY_CONNECTION"))
                result = nss_var_lookup_header(p, r, "Proxy-Connection");
            else if (strcEQ(var, "HTTP_ACCEPT"))
                result = nss_var_lookup_header(p, r, "Accept");
            else if (strlen(var) > 5 && strcEQn(var, "HTTP:", 5))
                /* all other headers from which we are still not know about */
                result = nss_var_lookup_header(p, r, var+5);
            break;

        case 'R':
        case 'r':
            if (strcEQ(var, "REQUEST_METHOD"))
                result = (char *)(r->method);
            else if (strcEQ(var, "REQUEST_SCHEME"))
#if AP_SERVER_MINORVERSION_NUMBER < 2 /* See comment in mod_nss.h */
                result = (char *)ap_http_method(r);
#else
                result = (char *)ap_http_scheme(r);
#endif
            else if (strcEQ(var, "REQUEST_URI"))
                result = r->uri;
            else if (strcEQ(var, "REQUEST_FILENAME"))
                result = r->filename;
            else if (strcEQ(var, "REMOTE_HOST"))
                result = (char *)ap_get_remote_host(r->connection,
					r->per_dir_config, REMOTE_NAME, NULL);
            else if (strcEQ(var, "REMOTE_IDENT"))
                result = (char *)ap_get_remote_logname(r);
            else if (strcEQ(var, "REMOTE_USER"))
                result = r->user;
            break;

        case 'S':
        case 's':
            if (strcEQn(var, "SSL", 3)) break; /* shortcut common case */

            if (strcEQ(var, "SERVER_ADMIN"))
                result = r->server->server_admin;
            else if (strcEQ(var, "SERVER_NAME"))
                result = (char *)ap_get_server_name(r);
            else if (strcEQ(var, "SERVER_PORT"))
                result = apr_psprintf(p, "%u", ap_get_server_port(r));
            else if (strcEQ(var, "SERVER_PROTOCOL"))
                result = r->protocol;
            else if (strcEQ(var, "SCRIPT_FILENAME"))
                result = r->filename;
            break;

        default:
            if (strcEQ(var, "PATH_INFO"))
                result = r->path_info;
            else if (strcEQ(var, "QUERY_STRING"))
                result = r->args;
            else if (strcEQ(var, "IS_SUBREQ"))
                result = (r->main != NULL ? "true" : "false");
            else if (strcEQ(var, "DOCUMENT_ROOT"))
                result = (char *)ap_document_root(r);
            else if (strcEQ(var, "AUTH_TYPE"))
                result = r->ap_auth_type;
            if (strcEQ(var, "THE_REQUEST"))
                result = r->the_request;
            break;
        }
    }

    /*
     * Connection stuff
     */
    if (result == NULL && c != NULL) {
        SSLConnRec *sslconn = myConnConfig(c);

        if (strlen(var) > 4 && strcEQn(var, "SSL_", 4)
            && (!sslconn || !sslconn->ssl) && othermod_var_lookup) {
            /* If mod_ssl is registered for this connection,
             * pass any SSL_* variable through to the mod_ssl module
             */
            return othermod_var_lookup(p, s, c, r, var);
        }

        if (strlen(var) > 4 && strcEQn(var, "SSL_", 4) 
                 && sslconn && sslconn->ssl)
            result = nss_var_lookup_ssl(p, c, var+4);
        else if (strcEQ(var, "REMOTE_ADDR"))
            result = c->client_ip;
        else if (strcEQ(var, "HTTPS")) {
            if (sslconn && sslconn->ssl)
                result = "on";
            else
                result = "off";
        }
    }

    /*
     * Totally independent stuff
     */
    if (result == NULL) {
        if (strlen(var) > 12 && strcEQn(var, "SSL_VERSION_", 12))
            result = nss_var_lookup_nss_version(p, var+12);
        else if (strcEQ(var, "SERVER_SOFTWARE"))
            result = (char *)ap_get_server_banner();
        else if (strcEQ(var, "API_VERSION")) {
            result = apr_psprintf(p, "%d", MODULE_MAGIC_NUMBER);
            resdup = FALSE;
        }
        else if (strcEQ(var, "TIME_YEAR")) {
            apr_time_exp_lt(&tm, apr_time_now());
            result = apr_psprintf(p, "%02d%02d",
                                 (tm.tm_year / 100) + 19, tm.tm_year % 100);
            resdup = FALSE;
        }
#define MKTIMESTR(format, tmfield) \
            apr_time_exp_lt(&tm, apr_time_now()); \
            result = apr_psprintf(p, format, tm.tmfield); \
            resdup = FALSE;
        else if (strcEQ(var, "TIME_MON")) {
            MKTIMESTR("%02d", tm_mon+1)
        }
        else if (strcEQ(var, "TIME_DAY")) {
            MKTIMESTR("%02d", tm_mday)
        }
        else if (strcEQ(var, "TIME_HOUR")) {
            MKTIMESTR("%02d", tm_hour)
        }
        else if (strcEQ(var, "TIME_MIN")) {
            MKTIMESTR("%02d", tm_min)
        }
        else if (strcEQ(var, "TIME_SEC")) {
            MKTIMESTR("%02d", tm_sec)
        }
        else if (strcEQ(var, "TIME_WDAY")) {
            MKTIMESTR("%d", tm_wday)
        }
        else if (strcEQ(var, "TIME")) {
            apr_time_exp_lt(&tm, apr_time_now());
            result = apr_psprintf(p,
                        "%02d%02d%02d%02d%02d%02d%02d", (tm.tm_year / 100) + 19,
                        (tm.tm_year % 100), tm.tm_mon+1, tm.tm_mday,
                        tm.tm_hour, tm.tm_min, tm.tm_sec);
            resdup = FALSE;
        }
        /* all other env-variables from the parent Apache process */
        else if (strlen(var) > 4 && strcEQn(var, "ENV:", 4)) {
            result = (char *)apr_table_get(r->notes, var+4);
            if (result == NULL)
                result = (char *)apr_table_get(r->subprocess_env, var+4);
            if (result == NULL)
                result = getenv(var+4);
        }
    }

    if (result != NULL && resdup)
        result = apr_pstrdup(p, result);
    if (result == NULL)
        result = "";
    return result;
}

static char *ssl_var_lookup(apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, char *var) {
    return nss_var_lookup(p, s, c, r, var);
}

static char *nss_var_lookup_header(apr_pool_t *p, request_rec *r, const char *name)
{
    char *hdr = NULL;

    if ((hdr = (char *)apr_table_get(r->headers_in, name)) != NULL)
        hdr = apr_pstrdup(p, hdr);
    return hdr;
}

static char *nss_var_lookup_ssl(apr_pool_t *p, conn_rec *c, char *var)
{
    SSLConnRec *sslconn = myConnConfig(c);
    char *result;
    CERTCertificate *xs;
    PRFileDesc *ssl;

    result = NULL;

    ssl = sslconn->ssl;
    if (strlen(var) > 8 && strcEQn(var, "VERSION_", 8)) {
        result = nss_var_lookup_nss_version(p, var+8);
    }
    else if (ssl != NULL && strcEQ(var, "PROTOCOL")) {
        result = (char *)nss_var_lookup_protocol_version(p, c);
    }
    else if (ssl != NULL && strcEQ(var, "SESSION_ID")) {
        char *idstr;
        SECItem *iditem;
 
        if ((iditem = SSL_GetSessionID(ssl)) == NULL)
            return NULL;

        /* Convert to base64 ASCII encoding */
        idstr = BTOA_DataToAscii(iditem->data, iditem->len);
        if (idstr) {
            result = apr_pstrdup(p, idstr);
            PORT_Free(idstr);
        }

        SECITEM_FreeItem(iditem, PR_TRUE);
    }
    else if (ssl != NULL && strlen(var) >= 6 && strcEQn(var, "CIPHER", 6)) {
        result = nss_var_lookup_nss_cipher(p, c, var+6);
    }
    else if (ssl != NULL && strlen(var) > 18 && strcEQn(var, "CLIENT_CERT_CHAIN_", 18)) {
        xs = SSL_PeerCertificate(ssl);
        if (xs != NULL) {
            result = nss_var_lookup_nss_cert_chain(p, xs, var+18);
            CERT_DestroyCertificate(xs);
        }
    }
    else if (ssl != NULL && strcEQ(var, "CLIENT_VERIFY")) {
        result = nss_var_lookup_nss_cert_verify(p, c);
    }
    else if (ssl != NULL && strlen(var) > 7 && strcEQn(var, "CLIENT_", 7)) {
        if ((xs = SSL_PeerCertificate(ssl)) != NULL) {
            result = nss_var_lookup_nss_cert(p, xs, var+7, c);
            CERT_DestroyCertificate(xs);
        }
    }
    else if (ssl != NULL && strlen(var) > 7 && strcEQn(var, "SERVER_", 7)) {
        if ((xs = SSL_LocalCertificate(ssl)) != NULL) {
            result = nss_var_lookup_nss_cert(p, xs, var+7, c);
            CERT_DestroyCertificate(xs);
        }
    }

    return result;
}

static char *nss_var_lookup_nss_cert(apr_pool_t *p, CERTCertificate *xs, char *var, conn_rec *c)
{
    char *result;
    BOOL resdup;
    char *xsname;

    result = NULL;
    resdup = TRUE;

    if (strcEQ(var, "M_VERSION")) {
        if (xs->version.data != NULL) {
            result = apr_psprintf(p, "%lu", DER_GetInteger(&xs->version)+1);
            resdup = FALSE;
        } else {
            result = apr_pstrdup(p, "UNKNOWN");
            resdup = FALSE;
        }
    }
    else if (strcEQ(var, "M_SERIAL")) {
        result = apr_psprintf(p, "%lu", DER_GetInteger(&xs->serialNumber));
        resdup = FALSE;
    }
    else if (strcEQ(var, "V_START")) {
        result = nss_var_lookup_nss_cert_valid(p, xs, CERT_NOTBEFORE);
    }
    else if (strcEQ(var, "V_END")) {
        result = nss_var_lookup_nss_cert_valid(p, xs, CERT_NOTAFTER);
    }
    else if (strcEQ(var, "V_REMAIN")) {
        result = ssl_var_lookup_ssl_cert_remain(p, xs);
        resdup = FALSE;
    }
    else if (strcEQ(var, "S_DN")) {
        xsname = CERT_NameToAscii(&xs->subject);
        result = apr_pstrdup(p, xsname);
        PR_Free(xsname);
        resdup = FALSE;
    }
    else if (strlen(var) > 5 && strcEQn(var, "S_DN_", 5)) {
        result = nss_var_lookup_nss_cert_dn(p, &xs->subject, var+5);
        resdup = FALSE;
    }
    else if (strcEQ(var, "I_DN")) {
        xsname = CERT_NameToAscii(&xs->issuer);
        result = apr_pstrdup(p, xsname);
        PR_Free(xsname);
        resdup = FALSE;
    }
    else if (strlen(var) > 5 && strcEQn(var, "I_DN_", 5)) {
        result = nss_var_lookup_nss_cert_dn(p, &xs->issuer, var+5);
        resdup = FALSE;
    }
    else if (strcEQ(var, "A_SIG")) {
        SSLChannelInfo      channel;
        SSLCipherSuiteInfo  suite;
        SSLConnRec *sslconn = myConnConfig(c);

        if (SSL_GetChannelInfo(sslconn->ssl, &channel, sizeof channel) ==
            SECSuccess && channel.length == sizeof channel &&
            channel.cipherSuite)
        {
            if (SSL_GetCipherSuiteInfo(channel.cipherSuite,
                &suite, sizeof suite) == SECSuccess)
            {
                result = apr_psprintf(p, "%s-%s", suite.macAlgorithmName, suite.authAlgorithmName);
            } 
        } else
            result = apr_pstrdup(p, "UNKNOWN");
        resdup = FALSE;
    }
    else if (strcEQ(var, "A_KEY")) {
        SSLChannelInfo      channel;
        SSLCipherSuiteInfo  suite;
        SSLConnRec *sslconn = myConnConfig(c);

        if (SSL_GetChannelInfo(sslconn->ssl, &channel, sizeof channel) ==
            SECSuccess && channel.length == sizeof channel &&
            channel.cipherSuite)
        {
            if (SSL_GetCipherSuiteInfo(channel.cipherSuite,
                &suite, sizeof suite) == SECSuccess)
            {
                result = apr_psprintf(p, "%s_%s", suite.keaTypeName, suite.authAlgorithmName);
            }
        } else
            result = apr_pstrdup(p, "UNKNOWN_UNKNOWN");

        resdup = FALSE;
    }
    else if (strcEQ(var, "CERT")) {
        result = nss_var_lookup_nss_cert_PEM(p, xs);
    }

    if (result != NULL && resdup)
        result = apr_pstrdup(p, result);
    return result;
}

static char *nss_var_lookup_nss_cert_dn(apr_pool_t *p, CERTName *cert, char *var)
{
    char *result;
    char *rv;

    result = NULL;
    rv = NULL;

    if (strcEQ(var, "C")) {
        rv = CERT_GetCountryName(cert);
    } else if (strcEQ(var, "ST")) {
        rv = CERT_GetStateName(cert);
    } else if (strcEQ(var, "SP")) { /* for compatibility */
        rv = CERT_GetStateName(cert);
    } else if (strcEQ(var, "L")) {
        rv = CERT_GetLocalityName(cert);
    } else if (strcEQ(var, "O")) {
        rv = CERT_GetOrgName(cert);
    } else if (strcEQ(var, "OU")) {
        rv = CERT_GetOrgUnitName(cert);
    } else if (strcEQ(var, "CN")) {
        rv = CERT_GetCommonName(cert);
    } else if (strcEQ(var, "UID")) {
        rv = CERT_GetCertUid(cert);
    } else if (strcEQ(var, "EMAIL")) {
        rv = CERT_GetCertEmailAddress(cert);
    } else {
        rv = NULL; /* catch any values we don't support */
    }

    if (rv) {
        result = apr_pstrdup(p, rv);
        PORT_Free(rv); /* so we can free with the right allocator */
    }

    return result;
}

static char *nss_var_lookup_nss_cert_valid(apr_pool_t *p, CERTCertificate *xs, int type)
{
    char *result;
    PRExplodedTime   printableTime;
    char             timeString[256];
    PRTime           notBefore, notAfter;

    CERT_GetCertTimes(xs, &notBefore, &notAfter);

    /* Converse time to local time and decompose it into components */
    if (type == CERT_NOTBEFORE) {
        PR_ExplodeTime(notBefore, PR_GMTParameters, &printableTime);
    } else {
        PR_ExplodeTime(notAfter, PR_GMTParameters, &printableTime);
    }

    PR_FormatTime(timeString, 256, "%b %d %H:%M:%S %Y GMT", &printableTime);

    result = apr_pstrdup(p, timeString);

    return result;
}

/* Return a string giving the number of days remaining until the cert
 * expires "0" if this can't be determined. 
 *
 * In mod_ssl this is more generic, passing in a time to calculate against,
 * but I see no point in converting the end date into a string and back again.
 */
static char *ssl_var_lookup_ssl_cert_remain(apr_pool_t *p, CERTCertificate *xs)
{
    PRTime           notBefore, notAfter;
    PRTime           now, diff;

    CERT_GetCertTimes(xs, &notBefore, &notAfter);
    now = PR_Now();

    /* Both times are relative to the epoch, so no TZ calcs are needed */
    diff = notAfter - now;

    /* PRTime is in microseconds so convert to seconds before days */
    diff = (diff / PR_USEC_PER_SEC) / (60*60*24);

    return (diff > 0) ? apr_itoa(p, diff) : apr_pstrdup(p, "0");
}

static char *nss_var_lookup_nss_cert_chain(apr_pool_t *p, CERTCertificate *cert, char *var)
{
    char *result;
    CERTCertificateList *chain = NULL;
    int n;

    result = NULL;

    chain = CERT_CertChainFromCert(cert, certUsageSSLClient, PR_TRUE);

    if (!chain)
        return NULL;

    if (strspn(var, "0123456789") == strlen(var)) {
        n = atoi(var);
        if (n <= chain->len-1) {
            CERTCertificate *c;
            c = CERT_FindCertByDERCert(CERT_GetDefaultCertDB(), &chain->certs[n]);
            result = nss_var_lookup_nss_cert_PEM(p, c);
            CERT_DestroyCertificate(c);
        }
    }

    CERT_DestroyCertificateList(chain);

    return result;
}

#define CERT_HEADER  "-----BEGIN CERTIFICATE-----\n"
#define CERT_TRAILER "\n-----END CERTIFICATE-----\n"
static char *nss_var_lookup_nss_cert_PEM(apr_pool_t *p, CERTCertificate *xs)
{
    char * result = NULL;
    char * tmp = NULL;
    int i, len;

    /* should never happen but we'll crash if it does */
    if (!xs)
        return NULL;

    tmp = BTOA_DataToAscii(xs->derCert.data,
                           xs->derCert.len);

    /* NSS uses \r\n as the line terminator. Remove \r so the output is
     * similar to mod_ssl. */
    i=0;
    len = strlen(tmp);
    while (tmp[i] != '\0') {
        if (tmp[i] == '\r') {
            memmove(&tmp[i], &tmp[i+1], 1+(len - i));
        }
        i++;
    }

    /* Allocate the size of the cert + header + footer + 1 */
    result = apr_palloc(p, strlen(tmp) + 29 + 27 + 1);
    strcpy(result, CERT_HEADER);
    strcat(result, tmp);
    strcat(result, CERT_TRAILER);
    result[strlen(tmp) + 29 + 27] = '\0';

    /* Clean up memory. */
    PR_Free(tmp);

    return result;
}

static char *nss_var_lookup_nss_cert_verify(apr_pool_t *p, conn_rec *c)
{
    SSLConnRec *sslconn = myConnConfig(c);
    char *result;
    PRFileDesc *ssl;
    SECStatus rv;
    CERTCertificate *xs;
    void *pinArg;

    result = NULL;
    ssl   = sslconn->ssl;
    xs    = SSL_PeerCertificate(ssl);
    pinArg = SSL_RevealPinArg(sslconn->ssl);

    if (xs == NULL)
        result = "NONE";
    else {
        rv = CERT_VerifyCertNow(CERT_GetDefaultCertDB(),
                                xs,
                                PR_TRUE,
                                certUsageSSLClient,
                                pinArg);

        if (rv == SECSuccess)
            result = "SUCCESS";
        else
            result = apr_psprintf(p, "FAILED"); /* FIXME, add more info? */
    }

    if (xs)
        CERT_DestroyCertificate(xs);

    return result;
}

static char *nss_var_lookup_nss_cipher(apr_pool_t *p, conn_rec *c, char *var)
{
    SSLConnRec *sslconn = myConnConfig(c);    
    char *result;
    BOOL resdup;
    PRFileDesc *ssl;
    int on, keySize, secretKeySize;
    char *cipher, *issuer, *subject;
    SECStatus secstatus = SECFailure;

    result = NULL;
    resdup = TRUE;

    on = keySize = secretKeySize = 0;
    cipher = issuer = subject = NULL;

    ssl = sslconn->ssl;

    if (ssl) {
        secstatus = SSL_SecurityStatus(ssl, &on, &cipher,
                                       &keySize, &secretKeySize, &issuer,
                                       &subject);
    }

    if (secstatus != SECSuccess)
        return NULL;

    if (ssl && strEQ(var, "")) {
        result = cipher;
    }
    else if (strcEQ(var, "_EXPORT"))
        result = (secretKeySize < 56 ? "true" : "false");
    else if (strcEQ(var, "_USEKEYSIZE")) {
        result = apr_psprintf(p, "%d", secretKeySize);
        resdup = FALSE;
    }
    else if (strcEQ(var, "_ALGKEYSIZE")) {
        result = apr_psprintf(p, "%d", keySize);
        resdup = FALSE;
    }
    else if (strcEQ(var, "_NAME")) {
        SSLChannelInfo      channel;
        SSLCipherSuiteInfo  suite;
        SSLConnRec *sslconn = myConnConfig(c);

        if (SSL_GetChannelInfo(sslconn->ssl, &channel, sizeof channel) ==
            SECSuccess && channel.length == sizeof channel &&
            channel.cipherSuite)
        {
            if (SSL_GetCipherSuiteInfo(channel.cipherSuite,
                &suite, sizeof suite) == SECSuccess)
            {
                result = apr_psprintf(p, "%s",  suite.cipherSuiteName);
            }
        } else
            result = apr_pstrdup(p, "UNKNOWN");

        resdup = FALSE;
    }

    if (result != NULL && resdup)
        result = apr_pstrdup(p, result);

    PR_Free(issuer);
    PR_Free(subject);

    return result;
}

static char *nss_var_lookup_nss_version(apr_pool_t *p, char *var)
{
    char *result;

    result = NULL;

    if (strEQ(var, "PRODUCT")) {
#if defined(SSL_PRODUCT_NAME) && defined(SSL_PRODUCT_VERSION)
        result = apr_psprintf(p, "%s/%s", SSL_PRODUCT_NAME, SSL_PRODUCT_VERSION);
#else
        result = NULL;
#endif
    }
    else if (strEQ(var, "INTERFACE")) {
        result = apr_psprintf(p, "mod_nss/%s", MOD_NSS_VERSION);
    }
    else if (strEQ(var, "LIBRARY")) {
        result = apr_psprintf(p, "NSS/%s", NSS_VERSION);
    }
    return result;
}

static char *nss_var_lookup_protocol_version(apr_pool_t *p, conn_rec *c) 
{
    char *result;
    SSLChannelInfo      channel;
    SSLCipherSuiteInfo  suite;
    SSLConnRec         *sslconn = myConnConfig(c);

    result = "UNKNOWN";

    if (SSL_GetChannelInfo(sslconn->ssl, &channel, sizeof channel) ==
        SECSuccess && channel.length == sizeof channel &&
        channel.cipherSuite) {
        if (SSL_GetCipherSuiteInfo(channel.cipherSuite,
                                &suite, sizeof suite) == SECSuccess) {
            switch (channel.protocolVersion) {
                case SSL_LIBRARY_VERSION_2:
                    result = "SSLv2";
                    break;
                case SSL_LIBRARY_VERSION_3_0:
                    result = "SSLv3";
                    break;
                case SSL_LIBRARY_VERSION_TLS_1_0:
                    /* 'TLSv1' has been deprecated; specify 'TLSv1.0' */
                    result = "TLSv1";
                    break;
                case SSL_LIBRARY_VERSION_TLS_1_1:
                    result = "TLSv1.1";
                    break;
            }
        }
    }

    result = apr_pstrdup(p, result);

    return result;
}

/*  _________________________________________________________________
**
**  SSL Extension to mod_log_config
**  _________________________________________________________________
*/

#include "mod_log_config.h"

static const char *nss_var_log_handler_c(request_rec *r, char *a);
static const char *nss_var_log_handler_x(request_rec *r, char *a);

/*
 * register us for the mod_log_config function registering phase
 * to establish %{...}c and to be able to expand %{...}x variables.
 */
void nss_var_log_config_register(apr_pool_t *p)
{
    static APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *log_pfn_register;

    log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);

    if (log_pfn_register) {
        log_pfn_register(p, "c", nss_var_log_handler_c, 0);
        log_pfn_register(p, "x", nss_var_log_handler_x, 0);
    }
    return;
}

/*
 * implement the %{..}c log function
 * (we are the only function)
 */
static const char *nss_var_log_handler_c(request_rec *r, char *a)
{
    SSLConnRec *sslconn = myConnConfig(r->connection);
    char *result; 

    if (sslconn == NULL || sslconn->ssl == NULL)
        return NULL;
    result = NULL;
    if (strEQ(a, "version"))
        result = nss_var_lookup(r->pool, r->server, r->connection, r, "SSL_PROTOCOL");
    else if (strEQ(a, "cipher"))
        result = nss_var_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER");
    else if (strEQ(a, "subjectdn") || strEQ(a, "clientcert"))
        result = nss_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENT_S_DN");
    else if (strEQ(a, "issuerdn") || strEQ(a, "cacert"))
        result = nss_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENT_I_DN");
    else if (strEQ(a, "errcode"))
        result = "-";
    if (result != NULL && result[0] == NUL)
        result = NULL;
    return result;
}

/*
 * extend the implementation of the %{..}x log function
 * (there can be more functions)
 */
static const char *nss_var_log_handler_x(request_rec *r, char *a)
{
    char *result;

    result = nss_var_lookup(r->pool, r->server, r->connection, r, a);
    if (result != NULL && result[0] == NUL)
        result = NULL;
    return result;
}

