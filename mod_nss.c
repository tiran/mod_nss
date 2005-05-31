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

    /*
     * Per-server context configuration directives
     */
    SSL_CMD_SRV(Engine, FLAG,
                "SSL switch for the protocol engine "
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
                "SSL Server Certificate nickname "
                "(`Server-Cert'")
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
#ifdef PROXY
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
    SSL_CMD_SRV(ProxyVerify, TAKE1,
               "SSL Proxy: whether to verify the remote certificate "
               "(`on' or `off')")
    SSL_CMD_SRV(ProxyVerifyDepth, TAKE1,
               "SSL Proxy: maximum certificate verification depth "
               "(`N' - number of intermediate certificates)")
    SSL_CMD_SRV(ProxyCACertificateFile, TAKE1,
               "SSL Proxy: file containing server certificates "
               "(`/path/to/file' - PEM encoded certificates)")
    SSL_CMD_SRV(ProxyCACertificatePath, TAKE1,
               "SSL Proxy: directory containing server certificates "
               "(`/path/to/dir' - contains PEM encoded certificates)")
    SSL_CMD_SRV(ProxyCARevocationPath, TAKE1,
                "SSL Proxy: CA Certificate Revocation List (CRL) path "
                "(`/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_SRV(ProxyCARevocationFile, TAKE1,
                "SSL Proxy: CA Certificate Revocation List (CRL) file "
                "(`/path/to/file' - PEM encoded)")
    SSL_CMD_SRV(ProxyMachineCertificateFile, TAKE1,
               "SSL Proxy: file containing client certificates "
               "(`/path/to/file' - PEM encoded certificates)")
    SSL_CMD_SRV(ProxyMachineCertificatePath, TAKE1,
               "SSL Proxy: directory containing client certificates "
               "(`/path/to/dir' - contains PEM encoded certificates)")

    /* Deprecated directives. */
    AP_INIT_RAW_ARGS("SSLLog", ap_set_deprecated, NULL, OR_ALL, 
      "SSLLog directive is no longer supported - use ErrorLog."),
    AP_INIT_RAW_ARGS("SSLLogLevel", ap_set_deprecated, NULL, OR_ALL, 
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

#ifdef PROXY
int nss_proxy_enable(conn_rec *c)
{
    SSLSrvConfigRec *sc = mySrvConfig(c->base_server);

    SSLConnRec *sslconn = nss_init_connection_ctx(c);

    if (!sc->proxy_enabled) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, c->base_server,
                     "SSL Proxy requested for %s but not enabled "
                     "[Hint: SSLProxyEngine]", sc->vhost_id);

        return 0;
    }

    sslconn->is_proxy = 1;
    sslconn->disabled = 0;

    return 1;
}
#endif

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

    SSL_ResetHandshake(ssl, PR_TRUE);

    return APR_SUCCESS;
}

static const char *nss_hook_http_method(const request_rec *r)
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
    nss_io_filter_register(p);

    ap_hook_pre_connection(nss_hook_pre_connection,NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config   (nss_init_Module,        NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_http_method   (nss_hook_http_method,   NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_default_port  (nss_hook_default_port,  NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config    (nss_hook_pre_config,    NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init    (nss_init_Child,         NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(nss_hook_Translate,     NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id (nss_hook_UserCheck,     NULL,NULL, APR_HOOK_FIRST);
    ap_hook_fixups        (nss_hook_Fixup,         NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(nss_hook_Access,        NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker  (nss_hook_Auth,          NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(nss_hook_ReadReq,    NULL,NULL, APR_HOOK_MIDDLE);

    nss_var_register();

#ifdef PROXY
    APR_REGISTER_OPTIONAL_FN(nss_proxy_enable);
#endif
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
