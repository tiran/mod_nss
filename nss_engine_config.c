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

/*  _________________________________________________________________
**
**  Support for Global Configuration
**  _________________________________________________________________
*/

#define SSL_MOD_CONFIG_KEY "nss_module"

SSLModConfigRec *nss_config_global_create(server_rec *s)
{
    apr_pool_t *pool = s->process->pool;
    SSLModConfigRec *mc;
    void *vmc;

    apr_pool_userdata_get(&vmc, SSL_MOD_CONFIG_KEY, pool);
    if (vmc) {
        return vmc; /* reused for lifetime of the server */
    }

    /*
     * allocate an own subpool which survives server restarts
     */
    mc = (SSLModConfigRec *)apr_palloc(pool, sizeof(*mc));
    mc->pPool = pool;

    /*
     * initialize per-module configuration
     */
    mc->nInitCount                  = 0;
    mc->pCertificateDatabase        = NULL;
    mc->pDBPrefix                   = NULL;
    mc->session_cache_size          = UNSET;
    mc->session_cache_timeout       = UNSET;
    mc->ssl3_session_cache_timeout  = UNSET;
    mc->pphrase_dialog_helper       = NULL;
    mc->pphrase_dialog_path         = NULL;
    mc->aRandSeed                   = apr_array_make(pool, 4,
                                                     sizeof(ssl_randseed_t));

    apr_pool_userdata_set(mc, SSL_MOD_CONFIG_KEY,
                          apr_pool_cleanup_null,
                          pool);

    return mc;
}

/*  _________________________________________________________________
**
**  Configuration handling
**  _________________________________________________________________
*/

static void modnss_ctx_init(modnss_ctx_t *mctx)
{
    mctx->sc                  = NULL; /* set during module init */

    mctx->as_server           = PR_TRUE;

    mctx->ssl2                = PR_FALSE;
    mctx->ssl3                = PR_FALSE;
    mctx->tls                 = PR_FALSE;
    mctx->tlsrollback         = PR_FALSE;

    mctx->enforce             = PR_TRUE;
    mctx->nickname            = NULL;
#ifdef NSS_ENABLE_ECC
    mctx->eccnickname         = NULL;
#endif
    mctx->servercert          = NULL;
    mctx->serverkey           = NULL;

    mctx->model               = NULL;

    mctx->auth.protocols      = NULL;
    mctx->auth.cipher_suite   = NULL;
    mctx->auth.verify_mode    = SSL_CVERIFY_UNSET;

}

static void modnss_ctx_init_proxy(SSLSrvConfigRec *sc,
                                  apr_pool_t *p)
{
    modnss_ctx_t *mctx;

    mctx = sc->proxy = apr_palloc(p, sizeof(*sc->proxy));

    modnss_ctx_init(mctx);

    mctx->as_server = PR_FALSE;
}

static void modnss_ctx_init_server(SSLSrvConfigRec *sc,
                                   apr_pool_t *p)
{
    modnss_ctx_t *mctx;

    mctx = sc->server = apr_palloc(p, sizeof(*sc->server));

    modnss_ctx_init(mctx);

    mctx->as_server = PR_TRUE;
}

static SSLSrvConfigRec *nss_config_server_new(apr_pool_t *p)
{
    SSLSrvConfigRec *sc = apr_palloc(p, sizeof(*sc));
    
    sc->mc                          = NULL;
    sc->ocsp                        = UNSET;
    sc->fips                        = UNSET;
    sc->enabled                     = UNSET;
    sc->proxy_enabled               = UNSET;
    sc->vhost_id                    = NULL;  /* set during module init */
    sc->vhost_id_len                = 0;     /* set during module init */
    sc->proxy                       = NULL;
    sc->server                      = NULL;

    modnss_ctx_init_proxy(sc, p);

    modnss_ctx_init_server(sc, p);

    return sc;
}

/*
 *  Create per-server SSL configuration
 */
void *nss_config_server_create(apr_pool_t *p, server_rec *s) {
    SSLSrvConfigRec *sc = nss_config_server_new(p);

    sc->mc = nss_config_global_create(s);

    return sc;
}

#define cfgMerge(el,unset)  mrg->el = (add->el == (unset)) ? base->el : add->el
#define cfgMergeArray(el)   mrg->el = apr_array_append(p, add->el, base->el)
#define cfgMergeString(el)  cfgMerge(el, NULL)
#define cfgMergeBool(el)    cfgMerge(el, UNSET)
#define cfgMergeInt(el)     cfgMerge(el, UNSET)

static void modnss_ctx_cfg_merge(modnss_ctx_t *base,
                                 modnss_ctx_t *add,
                                 modnss_ctx_t *mrg)
{
    cfgMerge(auth.protocols, NULL);
    cfgMerge(auth.cipher_suite, NULL);
    cfgMerge(auth.verify_mode, SSL_CVERIFY_UNSET);

    cfgMerge(nickname, NULL);
#ifdef NSS_ENABLE_ECC
    cfgMerge(eccnickname, NULL);
#endif
    cfgMerge(enforce, PR_TRUE);
}

static void modnss_ctx_cfg_merge_proxy(modnss_ctx_t *base,
                                       modnss_ctx_t *add,
                                       modnss_ctx_t *mrg)
{
    modnss_ctx_cfg_merge(base, add, mrg);
}

static void modnss_ctx_cfg_merge_server(modnss_ctx_t *base,
                                        modnss_ctx_t *add,
                                        modnss_ctx_t *mrg)
{
    modnss_ctx_cfg_merge(base, add, mrg);
}

/*
 *  Merge per-server SSL configurations
 */
void *nss_config_server_merge(apr_pool_t *p, void *basev, void *addv) {
    SSLSrvConfigRec *base = (SSLSrvConfigRec *)basev;
    SSLSrvConfigRec *add  = (SSLSrvConfigRec *)addv;
    SSLSrvConfigRec *mrg  = nss_config_server_new(p);

    cfgMerge(mc, NULL);
    cfgMergeBool(ocsp);
    cfgMergeBool(fips);
    cfgMergeBool(enabled);
    cfgMergeBool(proxy_enabled);

    modnss_ctx_cfg_merge_proxy(base->proxy, add->proxy, mrg->proxy);

    modnss_ctx_cfg_merge_server(base->server, add->server, mrg->server);

    return mrg;
}

/*
 *  Create per-directory SSL configuration
 */
void *nss_config_perdir_create(apr_pool_t *p, char *dir) {
    SSLDirConfigRec *dc = apr_palloc(p, sizeof(*dc));

    dc->bSSLRequired  = FALSE;
    dc->aRequirement  = apr_array_make(p, 4, sizeof(nss_require_t));
    dc->nOptions      = SSL_OPT_NONE|SSL_OPT_RELSET;
    dc->nOptionsAdd   = SSL_OPT_NONE;
    dc->nOptionsDel   = SSL_OPT_NONE;

    dc->szCipherSuite = NULL;
    dc->nVerifyClient = SSL_CVERIFY_UNSET;

    dc->szUserName    = NULL;

    return dc;
}
 
const char *nss_cmd_NSSRequireSSL(cmd_parms *cmd, void *dcfg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;

    dc->bSSLRequired = TRUE;
 
    return NULL;
}

const char *nss_cmd_NSSRequire(cmd_parms *cmd,
                               void *dcfg,
                               const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    nss_expr *expr;
    nss_require_t *require;

    if (!(expr = nss_expr_comp(cmd->pool, (char *)arg))) {
        return apr_pstrcat(cmd->pool, "NSSRequire: ",
                           nss_expr_get_error(), NULL);
    }

    require = apr_array_push(dc->aRequirement);
    require->cpExpr = apr_pstrdup(cmd->pool, arg);
    require->mpExpr = expr;

    return NULL;
}

void *nss_config_perdir_merge(apr_pool_t *p, void *basev, void *addv) {
    SSLDirConfigRec *base = (SSLDirConfigRec *)basev;
    SSLDirConfigRec *add  = (SSLDirConfigRec *)addv;
    SSLDirConfigRec *mrg  = (SSLDirConfigRec *)apr_palloc(p, sizeof(*mrg));

    cfgMerge(bSSLRequired, FALSE);
    cfgMergeArray(aRequirement);

    if (add->nOptions & SSL_OPT_RELSET) {
        mrg->nOptionsAdd =
            (base->nOptionsAdd & ~(add->nOptionsDel)) | add->nOptionsAdd;
        mrg->nOptionsDel =
            (base->nOptionsDel & ~(add->nOptionsAdd)) | add->nOptionsDel;
        mrg->nOptions    =
            (base->nOptions    & ~(mrg->nOptionsDel)) | mrg->nOptionsAdd;
    }
    else {
        mrg->nOptions    = add->nOptions;
        mrg->nOptionsAdd = add->nOptionsAdd;
        mrg->nOptionsDel = add->nOptionsDel;
    }

    cfgMergeString(szCipherSuite);
    cfgMerge(nVerifyClient, SSL_CVERIFY_UNSET);

    cfgMergeString(szUserName);

    return mrg;
}

const char *nss_cmd_NSSEngine(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->enabled = flag ? TRUE : FALSE;
 
    return NULL;
}

const char *nss_cmd_NSSFIPS(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    
    sc->fips = flag ? TRUE : FALSE;
 
    return NULL;
}

const char *nss_cmd_NSSOCSP(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->ocsp = flag ? TRUE : FALSE;

    return NULL;
}

const char *nss_cmd_NSSCertificateDatabase(cmd_parms *cmd,
                                           void *dcfg,
                                           const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);

    mc->pCertificateDatabase = arg;

    return NULL;
}

const char *nss_cmd_NSSDBPrefix(cmd_parms *cmd,
                                void *dcfg,
                               const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);

    mc->pDBPrefix = arg;

    return NULL;
}

const char *nss_cmd_NSSCipherSuite(cmd_parms *cmd,
                                   void *dcfg,
                                   const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;

    if (cmd->path) {
        dc->szCipherSuite = arg;
    }
    else {
        sc->server->auth.cipher_suite = arg;
    }

    return NULL;
}

static const char *nss_cmd_verify_parse(cmd_parms *parms,
                                        const char *arg,
                                        nss_verify_t *id)
{
    if (strcEQ(arg, "none") || strcEQ(arg, "off")) {
        *id = SSL_CVERIFY_NONE;
    }
    else if (strcEQ(arg, "optional")) {
        *id = SSL_CVERIFY_OPTIONAL;
    }
    else if (strcEQ(arg, "require") || strcEQ(arg, "on")) {
        *id = SSL_CVERIFY_REQUIRE;
    }
    else if (strcEQ(arg, "optional_no_ca")) {
        return apr_pstrcat(parms->temp_pool, parms->cmd->name,
                          "SSL_CVERIFY_OPTIONAL_NO_CA is not supported", NULL);
    }
    else {
        return apr_pstrcat(parms->temp_pool, parms->cmd->name,
                           ": Invalid argument '", arg, "'",
                           NULL);
    }

    return NULL;
}

const char *nss_cmd_NSSVerifyClient(cmd_parms *cmd,
                                    void *dcfg,
                                    const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
    nss_verify_t mode = SSL_CVERIFY_UNSET;
    const char *err;

    if ((err = nss_cmd_verify_parse(cmd, arg, &mode))) {
        return err;
    }

    if (cmd->path) {
        dc->nVerifyClient = mode;
    }
    else {
        sc->server->auth.verify_mode = mode;
    }

    return NULL;
}

const char *nss_cmd_NSSProtocol(cmd_parms *cmd,
                                void *dcfg,
                                const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->server->auth.protocols = arg;

    return NULL;
}

const char *nss_cmd_NSSNickname(cmd_parms *cmd,
                                void *dcfg,
                                const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->server->nickname = arg;

    return NULL;
}

#ifdef NSS_ENABLE_ECC
const char *nss_cmd_NSSECCNickname(cmd_parms *cmd,
                                void *dcfg,
                                const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->server->eccnickname = arg;

    return NULL;
}
#endif

const char *nss_cmd_NSSProxyEngine(cmd_parms *cmd, void *dcfg, int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
 
    sc->proxy_enabled = flag ? TRUE : FALSE;

    return NULL;
}
 
const char *nss_cmd_NSSProxyProtocol(cmd_parms *cmd,
                                     void *dcfg,
                                     const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->proxy->auth.protocols = arg;

    return NULL;
}

const char *nss_cmd_NSSProxyCipherSuite(cmd_parms *cmd,
                                        void *dcfg,
                                        const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);
 
    sc->proxy->auth.cipher_suite = arg;
 
    return NULL;
}
 
const char *nss_cmd_NSSProxyNickname(cmd_parms *cmd,
                                void *dcfg,
                                const char *arg)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->proxy->nickname = arg;

    return NULL;
}

const char *nss_cmd_NSSEnforceValidCerts(cmd_parms *cmd,
                                         void *dcfg,
                                         int flag)
{
    SSLSrvConfigRec *sc = mySrvConfig(cmd->server);

    sc->server->enforce = flag ? PR_TRUE : PR_FALSE;
 
    return NULL;
}

const char *nss_cmd_NSSSessionCacheTimeout(cmd_parms *cmd,
                                           void *dcfg,
                                           const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);

    mc->session_cache_timeout = atoi(arg);

    if (mc->session_cache_timeout < 0) {
        return "NSSSessionCacheTimeout: Invalid argument";
    }

    return NULL;
}

const char *nss_cmd_NSSSession3CacheTimeout(cmd_parms *cmd,
                                           void *dcfg,
                                           const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);

    mc->ssl3_session_cache_timeout = atoi(arg);

    if (mc->ssl3_session_cache_timeout < 0) {
        return "NSSSession3CacheTimeout: Invalid argument";
    }

    return NULL;
}

const char *nss_cmd_NSSSessionCacheSize(cmd_parms *cmd,
                                        void *dcfg,
                                        const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);

    mc->session_cache_size = atoi(arg);

    if (mc->session_cache_size < 0) {
        return "NSSSessionCacheTimeout: Invalid argument";
    }

    return NULL;
}

const char *nss_cmd_NSSPassPhraseDialog(cmd_parms *cmd,
                                        void *dcfg,
                                        const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);
    int arglen = strlen(arg);

    if (strcEQ(arg, "builtin")) {
        mc->pphrase_dialog_type  = SSL_PPTYPE_BUILTIN;
        mc->pphrase_dialog_path = NULL;
    }
    else if ((arglen > 5) && strEQn(arg, "file:", 5)) {
        apr_finfo_t finfo;
        apr_status_t rc;

        mc->pphrase_dialog_type  = SSL_PPTYPE_FILE;
        mc->pphrase_dialog_path = ap_server_root_relative(cmd->pool, arg+5);
        if (!mc->pphrase_dialog_path)
            return apr_pstrcat(cmd->pool,
                              "Invalid NSSPassPhraseDialog file: path ",
                               arg+5, NULL);
        rc = apr_stat(&finfo, mc->pphrase_dialog_path,
             APR_FINFO_TYPE|APR_FINFO_SIZE, cmd->pool);
        if ((rc != APR_SUCCESS) || (finfo.filetype != APR_REG)) {
            return apr_pstrcat(cmd->pool,
                               "NSSPassPhraseDialog: file '",
                               mc->pphrase_dialog_path,
                               "' does not exist", NULL);
        }
    }

    return NULL;
}

const char *nss_cmd_NSSPassPhraseHelper(cmd_parms *cmd,
                                        void *dcfg,
                                        const char *arg)
{
    SSLModConfigRec *mc = myModConfig(cmd->server);

    if (access(arg, R_OK|X_OK) != -1) {
        mc->pphrase_dialog_helper = arg;
    } else {
        return apr_pstrcat(cmd->pool,
                           "NSSPassPhraseHelper: ", mc->pphrase_dialog_path,
                           "does not exist or is not executable.", NULL);
    }

    return NULL;
}

const char *nss_cmd_NSSRandomSeed(cmd_parms *cmd,
                                  void *dcfg,
                                  const char *arg1,
                                  const char *arg2,
                                  const char *arg3)
{   
    SSLModConfigRec *mc = myModConfig(cmd->server);
    const char *err;
    ssl_randseed_t *seed;
    int arg2len = strlen(arg2);
    
    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
        return err;
    }
    
    /* Only run through this once. Otherwise the random seed sources are
     * pushed into the array for each server start (and we are guaranteed 2) */
    if (mc->nInitCount >= 1) {
        return NULL;
    }

    seed = apr_array_push(mc->aRandSeed);

    if (strcEQ(arg1, "startup")) {
        seed->nCtx = SSL_RSCTX_STARTUP;
    }
    else if (strcEQ(arg1, "connect")) {
        return apr_pstrcat(cmd->pool, "NSSRandomSeed: "
                           "mod_nss doesn't do per-connection random seeding",
                           NULL);
    }
    else {
        return apr_pstrcat(cmd->pool, "NSSRandomSeed: "
                           "invalid context: `", arg1, "'",
                           NULL);
    }

    if ((arg2len > 5) && strEQn(arg2, "file:", 5)) {
        seed->nSrc   = SSL_RSSRC_FILE;
        seed->cpPath = ap_server_root_relative(mc->pPool, arg2+5);
    }
    else if ((arg2len > 5) && strEQn(arg2, "exec:", 5)) {
        seed->nSrc   = SSL_RSSRC_EXEC;
        seed->cpPath = ap_server_root_relative(mc->pPool, arg2+5);
    }
    else if (strcEQ(arg2, "builtin")) {
        seed->nSrc   = SSL_RSSRC_BUILTIN;
        seed->cpPath = NULL;
    }
    else {
        seed->nSrc   = SSL_RSSRC_FILE;
        seed->cpPath = ap_server_root_relative(mc->pPool, arg2);
    }

    if (seed->nSrc != SSL_RSSRC_BUILTIN) {
        apr_finfo_t finfo;
        if (!seed->cpPath) {
            return apr_pstrcat(cmd->pool,
                               "Invalid NSSRandomSeed path ",
                               arg2, NULL);
        }
        if (apr_stat(&finfo, seed->cpPath, APR_FINFO_TYPE|APR_FINFO_SIZE, cmd->pool) != 0) {
            return apr_pstrcat(cmd->pool,
                               "NSSRandomSeed: source path '",
                               seed->cpPath, "' does not exist", NULL);
        }
    }

    if (!arg3) {
        seed->nBytes = 0; /* read whole file */
    }
    else {
        if (seed->nSrc == SSL_RSSRC_BUILTIN) {
            return "NSSRandomSeed: byte specification not "
                   "allowed for builtin seed source";
        }

        seed->nBytes = atoi(arg3);

        if (seed->nBytes < 0) {
            return "NSSRandomSeed: invalid number of bytes specified";
        }
    }

    return NULL;
}

const char *nss_cmd_NSSUserName(cmd_parms *cmd, void *dcfg,
                                const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    dc->szUserName = arg;
    return NULL;
}

const char *nss_cmd_NSSOptions(cmd_parms *cmd,
                               void *dcfg,
                               const char *arg)
{
    SSLDirConfigRec *dc = (SSLDirConfigRec *)dcfg;
    nss_opt_t opt;   
    int first = TRUE; 
    char action, *w; 
 
    while (*arg) {
        w = ap_getword_conf(cmd->pool, &arg);
        action = NUL;

        if ((*w == '+') || (*w == '-')) {
            action = *(w++);
        }
        else if (first) {
            dc->nOptions = SSL_OPT_NONE;
            first = FALSE;
        }

        if (strcEQ(w, "StdEnvVars")) {
            opt = SSL_OPT_STDENVVARS;
        }
        else if (strcEQ(w, "CompatEnvVars")) {
            opt = SSL_OPT_COMPATENVVARS;
        }
        else if (strcEQ(w, "ExportCertData")) {
            opt = SSL_OPT_EXPORTCERTDATA;
        }
        else if (strcEQ(w, "FakeBasicAuth")) {
            opt = SSL_OPT_FAKEBASICAUTH;
        }
        else if (strcEQ(w, "StrictRequire")) {
            opt = SSL_OPT_STRICTREQUIRE;
        }
        else if (strcEQ(w, "OptRenegotiate")) {
            opt = SSL_OPT_OPTRENEGOTIATE;
        }
        else {
            return apr_pstrcat(cmd->pool,
                               "NSSOptions: Illegal option '", w, "'",
                               NULL);
        }
        if (action == '-') {
            dc->nOptionsAdd &= ~opt;
            dc->nOptionsDel |=  opt;
            dc->nOptions    &= ~opt;
        }
        else if (action == '+') {
            dc->nOptionsAdd |=  opt;
            dc->nOptionsDel &= ~opt;
            dc->nOptions    |=  opt;
        }
        else {
            dc->nOptions    = opt;
            dc->nOptionsAdd = opt;
            dc->nOptionsDel = SSL_OPT_NONE;
        }
    }

    return NULL;
}
