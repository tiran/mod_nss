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
#include <assert.h>
#include "sslerr.h"

/*
 *  the table of configuration directives we provide
 */

#define SSL_CMD_ALL(name, args, desc) \
        AP_INIT_##args("NSS"#name, nss_cmd_NSS##name, \
                       NULL, RSRC_CONF|OR_AUTHCFG, desc),

#define SSL_CMD_SRV(name, args, desc) \
        AP_INIT_##args("NSS"#name, nss_cmd_NSS##name, \
                       NULL, RSRC_CONF, desc),

#define SSL_CMD_DIR(name, type, args, desc) \
        AP_INIT_##args("NSS"#name, nss_cmd_NSS##name, \
                       NULL, OR_##type, desc),

#define AP_END_CMD { NULL }

static const command_rec nss_config_cmds[] = {
    /*
     * Global (main-server) context configuration directives
     */
    SSL_CMD_SRV(CertificateDatabase, TAKE1,
                "SSL Server Certificate database "
                "(`/path/to/file'")
    SSL_CMD_SRV(DBPrefix, TAKE1,
                "NSS Database prefix (optional) "
                "(`my-prefix-'")
    SSL_CMD_SRV(SessionCacheTimeout, TAKE1,
                "SSL 2 Session Cache object lifetime "
                "(`N' - number of seconds)")
    SSL_CMD_SRV(Session3CacheTimeout, TAKE1,
                "SSL 3/TLS Session Cache object lifetime "
                "(`N' - number of seconds)")
    SSL_CMD_SRV(SessionCacheSize, TAKE1,
                "SSL Session Cache size "
                "(`N' - number of entries)")
    SSL_CMD_SRV(PassPhraseDialog, TAKE1,
                "SSL dialog mechanism for the pass phrase query "
                "(`builtin', `file:/path/to/file`")
    SSL_CMD_SRV(PassPhraseHelper, TAKE1,
                "Process to securely store SSL tokens to handle restarts "
                "(`/path/to/file`")
    SSL_CMD_SRV(OCSP, FLAG,
                "OCSP (Online Certificate Status Protocol)"
                "(`on', `off')")
     SSL_CMD_SRV(RandomSeed, TAKE23,
                "SSL Pseudo Random Number Generator (PRNG) seeding source "
                "(`startup builtin|file:/path|exec:/path [bytes]')")

    /*
     * Per-server context configuration directives
     */
    SSL_CMD_SRV(Engine, FLAG,
                "SSL switch for the protocol engine "
                "(`on', `off')")
    SSL_CMD_SRV(FIPS, FLAG,
                "FIPS 140-1 mode "
                "(`on', `off')")
    SSL_CMD_ALL(CipherSuite, TAKE1,
                "Comma-delimited list of permitted SSL Ciphers, + to enable, - to disable "
                "(`[+-]XXX,...,[+-]XXX' - see manual)")
    SSL_CMD_SRV(Protocol, RAW_ARGS,
                "Enable the various SSL protocols"
                "(`[SSLv2|SSLv3|TLSv1|all] ...' - see manual)")
    SSL_CMD_ALL(VerifyClient, TAKE1,
                "SSL Client Authentication "
                "(`none', `optional', `require'")
    SSL_CMD_SRV(Nickname, TAKE1,
                "SSL RSA Server Certificate nickname "
                "(`Server-Cert'")
#ifdef NSS_ENABLE_ECC
    SSL_CMD_SRV(ECCNickname, TAKE1,
                "SSL ECC Server Certificate nickname "
                "(`Server-Cert'")
#endif
    SSL_CMD_SRV(EnforceValidCerts, FLAG,
                "Require a valid, trust, non-expired server certificate (default on)"
                "(`on', `off'")
    SSL_CMD_ALL(UserName, TAKE1,
		"Set user name to SSL variable value")
    /*
     * Per-directory context configuration directives
     */
    SSL_CMD_DIR(Options, OPTIONS, RAW_ARGS,
               "Set one or more options to configure the SSL engine"
               "(`[+-]option[=value] ...' - see manual)")
    SSL_CMD_DIR(RequireSSL, AUTHCFG, NO_ARGS,
               "Require the SSL protocol for the per-directory context "
               "(no arguments)")
    SSL_CMD_DIR(Require, AUTHCFG, RAW_ARGS,
               "Require a boolean expression to evaluate to true for granting access" 
               "(arbitrary complex boolean expression - see manual)")
    /* 
     * Proxy configuration for remote SSL connections
     */
    SSL_CMD_SRV(ProxyEngine, FLAG,
                "SSL switch for the proxy protocol engine "
                "(`on', `off')")
    SSL_CMD_SRV(ProxyProtocol, RAW_ARGS,
               "SSL Proxy: enable or disable SSL protocol flavors "
               "(`[+-][SSLv2|SSLv3|TLSv1] ...' - see manual)")
    SSL_CMD_SRV(ProxyCipherSuite, TAKE1,
               "SSL Proxy: colon-delimited list of permitted SSL ciphers "
               "(`XXX:...:XXX' - see manual)")
    SSL_CMD_SRV(ProxyNickname, TAKE1,
               "SSL Proxy: client certificate Nickname to be for proxy connections "
               "(`nickname')")

#ifdef IGNORE
    /* Deprecated directives. */
    AP_INIT_RAW_ARGS("NSSLog", ap_set_deprecated, NULL, OR_ALL, 
      "SSLLog directive is no longer supported - use ErrorLog."),
    AP_INIT_RAW_ARGS("NSSLogLevel", ap_set_deprecated, NULL, OR_ALL, 
      "SSLLogLevel directive is no longer supported - use LogLevel."),
#endif
    
    AP_END_CMD
};

/*
 *  the various processing hooks
 */

static int nss_hook_pre_config(apr_pool_t *pconf,
                               apr_pool_t *plog,
                               apr_pool_t *ptemp)
{
    /* Register us to handle mod_log_config %c/%x variables */
    nss_var_log_config_register(pconf);

    return OK;
}

static SSLConnRec *nss_init_connection_ctx(conn_rec *c)
{
    SSLConnRec *sslconn = myConnConfig(c);

    if (sslconn) {
        return sslconn;
    }

    sslconn = apr_pcalloc(c->pool, sizeof(*sslconn));

    sslconn->is_proxy = 0;
    sslconn->disabled = 0;
    sslconn->non_nss_request = 0;
    sslconn->ssl = NULL;

    myConnConfigSet(c, sslconn);

    return sslconn;
}

int nss_proxy_enable(conn_rec *c)
{
    SSLSrvConfigRec *sc = mySrvConfig(c->base_server);

    SSLConnRec *sslconn = nss_init_connection_ctx(c);

    if (!sc->proxy_enabled) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, c->base_server,
                     "SSL Proxy requested for %s but not enabled "
                     "[Hint: NSSProxyEngine]", sc->vhost_id);

        return 0;
    }

    sslconn->is_proxy = 1;
    sslconn->disabled = 0;

    return 1;
}

int nss_engine_disable(conn_rec *c)
{
    SSLSrvConfigRec *sc = mySrvConfig(c->base_server);

    SSLConnRec *sslconn;

    if (!sc->enabled) {
        return 0;
    }

    sslconn = nss_init_connection_ctx(c);

    sslconn->disabled = 1;

    return 1;
}

/* Callback for an incoming certificate that is not valid */

SECStatus NSSBadCertHandler(void *arg, PRFileDesc * socket)
{
    conn_rec *c = (conn_rec *)arg;
    PRErrorCode err = PR_GetError();
    SECStatus rv = SECFailure;
    CERTCertificate *peerCert = SSL_PeerCertificate(socket);
                                                                                
    switch (err) {
        case SSL_ERROR_BAD_CERT_DOMAIN:
            if (c->remote_host != NULL) {
                rv = CERT_VerifyCertName(peerCert, c->remote_host);
                if (rv != SECSuccess) {
                    char *remote = CERT_GetCommonName(&peerCert->subject);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                        "SSL Proxy: Possible man-in-the-middle attack. The remove server is %s, we expected %s", remote, c->remote_host);
                    PORT_Free(remote);
                }
            } else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                    "SSL Proxy: I don't have the name of the host we're supposed to connect to so I can't verify that we are connecting to who we think we should be. Giving up. Hint: See Apache bug 36468.");
            }
            break;
        default:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                "Bad remote server certificate: %d", err);
            nss_log_nss_error(APLOG_MARK, APLOG_ERR, NULL);
            break;
    }
    return rv;
}

/* Callback to pull the client certificate upon server request */

static SECStatus NSSGetClientAuthData(void *arg, PRFileDesc *socket,
                                    CERTDistNames *caNames,
                                    CERTCertificate **pRetCert,/*return */
                                    SECKEYPrivateKey **pRetKey)
{
    CERTCertificate *               cert;
    SECKEYPrivateKey *              privKey;
    void *                          proto_win = NULL;
    SECStatus                       rv = SECFailure;
    char *                          localNickName = (char *)arg;

    proto_win = SSL_RevealPinArg(socket);

    if (localNickName) {
        cert = CERT_FindUserCertByUsage(CERT_GetDefaultCertDB(),
                                    localNickName, certUsageSSLClient,
                                    PR_FALSE, proto_win);
        if (cert) {
            privKey = PK11_FindKeyByAnyCert(cert, proto_win);
            if (privKey) {
                rv = SECSuccess;
            } else {
                CERT_DestroyCertificate(cert);
            }
        } 

        if (rv == SECSuccess) {
            *pRetCert = cert;
            *pRetKey  = privKey;
        }
    }

    return rv;
}

static int nss_hook_pre_connection(conn_rec *c, void *csd)
{
    SSLSrvConfigRec *sc = mySrvConfig(c->base_server);
    PRFileDesc *ssl;
    SSLConnRec *sslconn = myConnConfig(c);
    modnss_ctx_t *mctx;

    /*
     * Immediately stop processing if SSL is disabled for this connection
     */
    if (!(sc && (sc->enabled ||
                 (sslconn && sslconn->is_proxy))))
    {
        return DECLINED;
    }

    /*
     * Create SSL context
     */
    if (!sslconn) {
        sslconn = nss_init_connection_ctx(c);
    }

    if (sslconn->disabled) {
        return DECLINED;
    }

    /*
     * Remember the connection information for
     * later access inside callback functions
     */

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, c->base_server,
                 "Connection to child %ld established "
                 "(server %s, client %s)", c->id, sc->vhost_id, 
                 c->remote_ip ? c->remote_ip : "unknown");

    mctx = sslconn->is_proxy ? sc->proxy : sc->server;

    /*
     * Create a new SSL connection with the configured server SSL context and
     * attach this to the socket. Additionally we register this attachment
     * so we can detach later.
     */
    ssl = nss_io_new_fd();
    ssl = SSL_ImportFD(mctx->model, ssl);

    if (!(ssl)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, c->base_server,
                     "Unable to create a new SSL connection from the SSL "
                     "context");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, c->base_server);

        c->aborted = 1;

        return DECLINED; /* XXX */
    }

    sslconn->ssl = ssl;
    sslconn->client_socket = csd;

    nss_io_filter_init(c, ssl);

    SSL_ResetHandshake(ssl, mctx->as_server);

    /* If we are doing a client connection, set our own bad certificate
     * handler and register the nickname we want to use in case client
     * authentication is requested.
     */
    if (!mctx->as_server) {
        if (SSL_BadCertHook(ssl, (SSLBadCertHandler) NSSBadCertHandler, c) != SECSuccess)
        {
            /* errors are reported in the certificate handler */
            return DECLINED;
        }
        if (mctx->nickname) {
            if (SSL_GetClientAuthDataHook(ssl, NSSGetClientAuthData,
                                          (void*)mctx->nickname) != SECSuccess)
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, c->base_server,
                    "Unable to register client authentication callback");
                return DECLINED;
            }
        }
    }

    return APR_SUCCESS;
}

static const char *nss_hook_http_scheme(const request_rec *r)
{
    SSLSrvConfigRec *sc = mySrvConfig(r->server);

    if (sc->enabled == FALSE) {
        return NULL;
    }

    return "https";
}

static apr_port_t nss_hook_default_port(const request_rec *r)
{
    SSLSrvConfigRec *sc = mySrvConfig(r->server);

    if (sc->enabled == FALSE) {
        return 0;
    }

    return 443;
}

/*
 *  the module registration phase
 */

static void nss_register_hooks(apr_pool_t *p)
{
    /* nss_hook_ReadReq needs to use the BrowserMatch settings so must
     * run after mod_setenvif's post_read_request hook. */ 
    static const char *pre_prr[] = { "mod_setenvif.c", NULL };

    nss_io_filter_register(p);

    ap_hook_pre_connection(nss_hook_pre_connection,NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config   (nss_init_Module,        NULL,NULL, APR_HOOK_MIDDLE);
#if AP_SERVER_MINORVERSION_NUMBER < 2 /* See comment in mod_nss.h */
    ap_hook_http_method   (nss_hook_http_scheme,   NULL,NULL, APR_HOOK_MIDDLE);
#else
    ap_hook_http_scheme   (nss_hook_http_scheme,   NULL,NULL, APR_HOOK_MIDDLE);
#endif
    ap_hook_default_port  (nss_hook_default_port,  NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config    (nss_hook_pre_config,    NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init    (nss_init_Child,         NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id (nss_hook_UserCheck,     NULL,NULL, APR_HOOK_FIRST);
    ap_hook_fixups        (nss_hook_Fixup,         NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(nss_hook_Access,        NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker  (nss_hook_Auth,          NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(nss_hook_ReadReq, pre_prr,NULL, APR_HOOK_MIDDLE);

    nss_var_register();

    APR_REGISTER_OPTIONAL_FN(nss_proxy_enable);
    APR_REGISTER_OPTIONAL_FN(nss_engine_disable);
}

module AP_MODULE_DECLARE_DATA nss_module = {
    STANDARD20_MODULE_STUFF,
    nss_config_perdir_create,   /* create per-dir    config structures */
    nss_config_perdir_merge,    /* merge  per-dir    config structures */
    nss_config_server_create,   /* create per-server config structures */
    nss_config_server_merge,    /* merge  per-server config structures */
    nss_config_cmds,            /* table of configuration directives   */
    nss_register_hooks          /* register hooks */
};
