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
#include "apr_thread_proc.h"
#include "ap_mpm.h"
#include "secmod.h"
#include "sslerr.h"
#include "pk11func.h"
#include "ocsp.h"
#include "keyhi.h"
#include "cert.h"

static SECStatus ownBadCertHandler(void *arg, PRFileDesc * socket);
static SECStatus ownHandshakeCallback(PRFileDesc * socket, void *arg);
static SECStatus NSSHandshakeCallback(PRFileDesc *socket, void *arg);
static CERTCertificate* FindServerCertFromNickname(const char* name);
SECStatus nss_AuthCertificate(void *arg, PRFileDesc *socket, PRBool checksig, PRBool isServer);

/*
 * Global variables defined in this file.
 */
char* INTERNAL_TOKEN_NAME = "internal                         ";

cipher_properties ciphers_def[ciphernum] =
{
    /* SSL2 cipher suites */
    {"rc4", SSL_EN_RC4_128_WITH_MD5, 0, SSL2},
    {"rc4export", SSL_EN_RC4_128_EXPORT40_WITH_MD5, 0, SSL2},
    {"rc2", SSL_EN_RC2_128_CBC_WITH_MD5, 0, SSL2},
    {"rc2export", SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5, 0, SSL2},
    {"des", SSL_EN_DES_64_CBC_WITH_MD5, 0, SSL2},
    {"desede3", SSL_EN_DES_192_EDE3_CBC_WITH_MD5, 0, SSL2},
    /* SSL3/TLS cipher suites */
    {"rsa_rc4_128_md5", SSL_RSA_WITH_RC4_128_MD5, 0, SSL3 | TLS},
    {"rsa_rc4_128_sha", SSL_RSA_WITH_RC4_128_SHA, 0, SSL3 | TLS},
    {"rsa_3des_sha", SSL_RSA_WITH_3DES_EDE_CBC_SHA, 0, SSL3 | TLS},
    {"rsa_des_sha", SSL_RSA_WITH_DES_CBC_SHA, 0, SSL3 | TLS},
    {"rsa_rc4_40_md5", SSL_RSA_EXPORT_WITH_RC4_40_MD5, 0, SSL3 | TLS},
    {"rsa_rc2_40_md5", SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5, 0, SSL3 | TLS},
    {"rsa_null_md5", SSL_RSA_WITH_NULL_MD5, 0, SSL3 | TLS},
    {"rsa_null_sha", SSL_RSA_WITH_NULL_SHA, 0, SSL3 | TLS},
    {"fips_3des_sha", SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA, 0, SSL3 | TLS},
    {"fips_des_sha", SSL_RSA_FIPS_WITH_DES_CBC_SHA, 0, SSL3 | TLS},
    {"fortezza", SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA, 1, SSL3 | TLS},
    {"fortezza_rc4_128_sha", SSL_FORTEZZA_DMS_WITH_RC4_128_SHA, 1, SSL3 | TLS},
    {"fortezza_null", SSL_FORTEZZA_DMS_WITH_NULL_SHA, 1, SSL3 | TLS},
    /* TLS 1.0: Exportable 56-bit Cipher Suites. */
    {"rsa_des_56_sha", TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA, 0, SSL3 | TLS},
    {"rsa_rc4_56_sha", TLS_RSA_EXPORT1024_WITH_RC4_56_SHA, 0, SSL3 | TLS},
    /* AES ciphers.*/
    {"rsa_aes_128_sha", TLS_RSA_WITH_AES_128_CBC_SHA, 0, SSL3 | TLS},
    {"rsa_aes_256_sha", TLS_RSA_WITH_AES_256_CBC_SHA, 0, SSL3 | TLS},
#ifdef NSS_ENABLE_ECC
    /* ECC ciphers.*/
    {"ecdh_ecdsa_null_sha", TLS_ECDH_ECDSA_WITH_NULL_SHA, 0, TLS},
    {"ecdh_ecdsa_rc4_128_sha", TLS_ECDH_ECDSA_WITH_RC4_128_SHA, 0, TLS},
    {"ecdh_ecdsa_3des_sha", TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, 0, TLS},
    {"ecdh_ecdsa_aes_128_sha", TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, 0, TLS},
    {"ecdh_ecdsa_aes_256_sha", TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, 0, TLS},
    {"ecdhe_ecdsa_null_sha", TLS_ECDHE_ECDSA_WITH_NULL_SHA, 0, TLS},
    {"ecdhe_ecdsa_rc4_128_sha", TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 0, TLS},
    {"ecdhe_ecdsa_3des_sha", TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, 0, TLS},
    {"ecdhe_ecdsa_aes_128_sha", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 0, TLS},
    {"ecdhe_ecdsa_aes_256_sha", TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 0, TLS},
    {"ecdh_rsa_null_sha", TLS_ECDH_RSA_WITH_NULL_SHA, 0, TLS},
    {"ecdh_rsa_128_sha", TLS_ECDH_RSA_WITH_RC4_128_SHA, 0, TLS},
    {"ecdh_rsa_3des_sha", TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, 0, TLS},
    {"ecdh_rsa_aes_128_sha", TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, 0, TLS},
    {"ecdh_rsa_aes_256_sha", TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, 0, TLS},
    {"ecdhe_rsa_null", TLS_ECDHE_RSA_WITH_NULL_SHA, 0, TLS},
    {"ecdhe_rsa_rc4_128_sha", TLS_ECDHE_RSA_WITH_RC4_128_SHA, 0, TLS},
    {"ecdhe_rsa_3des_sha", TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 0, TLS},
    {"ecdhe_rsa_aes_128_sha", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 0, TLS},
    {"ecdhe_rsa_aes_256_sha", TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 0, TLS},
    {"ecdh_anon_null_sha", TLS_ECDH_anon_WITH_NULL_SHA, 0, TLS},
    {"ecdh_anon_rc4_128sha", TLS_ECDH_anon_WITH_RC4_128_SHA, 0, TLS},
    {"ecdh_anon_3des_sha", TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, 0, TLS},
    {"ecdh_anon_aes_128_sha", TLS_ECDH_anon_WITH_AES_128_CBC_SHA, 0, TLS},
    {"ecdh_anon_aes_256_sha", TLS_ECDH_anon_WITH_AES_256_CBC_SHA, 0, TLS},
#endif
};

static char *version_components[] = {
    "SSL_VERSION_PRODUCT",
    "SSL_VERSION_INTERFACE",
    "SSL_VERSION_LIBRARY",
    NULL
}; 

static char *nss_add_version_component(apr_pool_t *p,
                                       server_rec *s,
                                       char *name)
{   
    char *val = nss_var_lookup(p, s, NULL, NULL, name);

    if (val && *val) {
        ap_add_version_component(p, val);
    }

    return val;
}
 
static void nss_add_version_components(apr_pool_t *p,
                                       server_rec *s)
{
    char *vals[sizeof(version_components)/sizeof(char *)];
    int i;

    for (i=0; version_components[i]; i++) {
        vals[i] = nss_add_version_component(p, s,
                                            version_components[i]);
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "Server: %s, Interface: %s, Library: %s",
                 AP_SERVER_BASEVERSION,
                 vals[1],  /* SSL_VERSION_INTERFACE */
                 vals[2]); /* SSL_VERSION_LIBRARY */
}

/*
 *  Initialize SSL library
 *
 */
static void nss_init_SSLLibrary(server_rec *base_server)
{
    SECStatus rv;
    SSLModConfigRec *mc = myModConfig(base_server);
    SSLSrvConfigRec *sc; 
    char cwd[PATH_MAX];
    server_rec *s;
    int fipsenabled = FALSE;
    int ocspenabled = FALSE;
    int ocspdefault = FALSE;
    const char * ocspurl = NULL;
    const char * ocspname = NULL;


    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);

        if (sc->fips == TRUE) {
            fipsenabled = TRUE;
        }

        if (sc->ocsp == TRUE) {
            ocspenabled = TRUE;
        }

        if (sc->ocsp_default == TRUE) {
            ocspdefault = TRUE;
            ocspurl = sc->ocsp_url;
            ocspname = sc->ocsp_name;
            if ((ocspurl == NULL) || (ocspname == NULL)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
                    "When NSSOCSPDefaultResponder is enabled both a default URL (NSSOCSPDefaultUrl) and certificate nickname (NSSOCSPDefaultName) are required.");
                if (mc->nInitCount == 1)
                    nss_die();
                else
                    return;
            }
        }
    }

    /* We need to be in the same directory as libnssckbi.so to load the
     * root certificates properly.
     */
    if (getcwd(cwd, PATH_MAX) == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
            "Unable to determine current working directory");
            if (mc->nInitCount == 1)
                nss_die();
            else
                return;
    }
    if (chdir(mc->pCertificateDatabase) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
            "Unable to change directory to %s", mc->pCertificateDatabase);
        if (mc->nInitCount == 1)
            nss_die();
        else
            return;
    }
    /* Initialize NSS and open the certificate database read-only. */
    rv = NSS_Initialize(mc->pCertificateDatabase, mc->pDBPrefix, mc->pDBPrefix, "secmod.db", NSS_INIT_READONLY);
    if (chdir(cwd) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
            "Unable to change directory to %s", cwd);
        if (mc->nInitCount == 1)
            nss_die();
        else
            return;
    }

    /* Assuming everything is ok so far, check the cert database password(s). */
    if (rv != SECSuccess) {
        NSS_Shutdown();
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
            "NSS_Initialize failed. Certificate database: %s.", mc->pCertificateDatabase != NULL ? mc->pCertificateDatabase : "not set in configuration");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, base_server);
        if (mc->nInitCount == 1)
            nss_die();
        else
            return;
    }

    if (fipsenabled) {
        if (!PK11_IsFIPS()) {
            char * internal_name = PR_smprintf("%s",
                SECMOD_GetInternalModule()->commonName);

            if ((SECMOD_DeleteInternalModule(internal_name) != SECSuccess) ||
                 !PK11_IsFIPS()) {
                 ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
                     "Unable to enable FIPS mode on certificate database %s.", mc->pCertificateDatabase);
                 NSS_Shutdown();
                 nss_log_nss_error(APLOG_MARK, APLOG_ERR, base_server);
                 if (mc->nInitCount == 1)
                     nss_die();
                 else
                     return;
            }
            PR_smprintf_free(internal_name);
        } /* FIPS is already enabled, nothing to do */
    }

    if (nss_Init_Tokens(base_server) != SECSuccess) {
        NSS_Shutdown();
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
            "NSS initialization failed. Certificate database: %s.", mc->pCertificateDatabase != NULL ? mc->pCertificateDatabase : "not set in configuration");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, base_server);
        if (mc->nInitCount == 1)
            nss_die();
        else
            return;
    }

    if (NSS_SetDomesticPolicy() != SECSuccess) {
        NSS_Shutdown();
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
                 "NSS set domestic policy failed on certificate database %s.", mc->pCertificateDatabase);
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, base_server);
        if (mc->nInitCount == 1)
            nss_die();
        else
            return;
    }

    if (ocspenabled) {
        CERT_EnableOCSPChecking(CERT_GetDefaultCertDB());
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, base_server,
            "OCSP is enabled.");

        /* We ensure that ocspname and ocspurl are not NULL above. */
        if (ocspdefault) {
            SECStatus sv;
 
            sv = CERT_SetOCSPDefaultResponder(CERT_GetDefaultCertDB(),
                     ocspurl, ocspname);

            if (sv == SECFailure) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
                    "Unable to set OCSP default responder nickname %s.", ocspname);
                nss_log_nss_error(APLOG_MARK, APLOG_ERR, base_server);
                if (mc->nInitCount == 1)
                    nss_die();
                else
                    return;
            }

            sv = CERT_EnableOCSPDefaultResponder(CERT_GetDefaultCertDB());
            if (sv == SECFailure) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
                    "Unable to enable the OCSP default responder, %s (this shouldn't happen).", ocspname);
                nss_log_nss_error(APLOG_MARK, APLOG_ERR, base_server);
                if (mc->nInitCount == 1)
                    nss_die();
                else
                    return;
            }
        }
    }

    /* 
     * Seed the Pseudo Random Number Generator (PRNG)
     * only need ptemp here; nothing inside allocated from the pool
     * needs to live once we return from nss_rand_seed().
     */
    nss_rand_seed(base_server, mc->ptemp, SSL_RSCTX_STARTUP, "Init: ");
}

int nss_init_Module(apr_pool_t *p, apr_pool_t *plog,
                    apr_pool_t *ptemp,
                    server_rec *base_server)
{
    SSLModConfigRec *mc = myModConfig(base_server);
    SSLSrvConfigRec *sc; 
    server_rec *s;
    int sslenabled = FALSE;
    int fipsenabled = FALSE;
    int threaded = 0;

    mc->nInitCount++;

    mc->ptemp = ptemp;
 
    /*
     * Any init round fixes the global config
     */
    nss_config_global_create(base_server); /* just to avoid problems */

    /*
     * Fix up any global settings that aren't in the configuration
     */
    if (mc->session_cache_timeout == UNSET) {
        mc->session_cache_timeout = SSL_SESSION_CACHE_TIMEOUT;
    }

    if (mc->ssl3_session_cache_timeout == UNSET) {
        mc->ssl3_session_cache_timeout = SSL3_SESSION_CACHE_TIMEOUT;
    }

    if (mc->session_cache_size == UNSET) {
        mc->session_cache_size = SSL_SESSION_CACHE_SIZE;
    }

    if (mc->pphrase_dialog_type == SSL_PPTYPE_UNSET) {
        mc->pphrase_dialog_type = SSL_PPTYPE_BUILTIN;
    }

    /*
     *  try to fix the configuration and open the dedicated SSL
     *  logfile as early as possible
     */
    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);

        if (sc->server) {
            sc->server->sc = sc;
        }

        if (sc->proxy) {
            sc->proxy->sc = sc;
        }

        /*
         * Create the server host:port string because we need it a lot
         */
        sc->vhost_id = nss_util_vhostid(p, s);
        sc->vhost_id_len = strlen(sc->vhost_id);

        /* Fix up stuff that may not have been set */
        if (sc->fips == UNSET) {
            sc->fips = FALSE;
        }

        if (sc->ocsp == UNSET) {
            sc->ocsp = FALSE;
        }

        if (sc->ocsp_default == UNSET) {
            sc->ocsp_default = FALSE;
        }

        /* If any servers have SSL, we want sslenabled set so we
         * can initialize the database. fipsenabled is similar. If
         * any of the servers have it set, they all will need to use
         * FIPS mode.
         */

        if (sc->enabled == UNSET) {
            sc->enabled = FALSE;
        }

        if (sc->proxy_enabled == UNSET) {
            sc->proxy_enabled = FALSE;
        }

        if ((sc->enabled == TRUE) || (sc->proxy_enabled == TRUE)) {
            sslenabled = TRUE;
        }

        if (sc->fips == TRUE) {
            fipsenabled = TRUE;
        }
    }

    if (sslenabled == FALSE) {
        return OK;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "Init: %snitializing NSS library", mc->nInitCount == 1 ? "I" : "Re-i");

    /* Do we need to fire up our password helper? */
    if (mc->nInitCount == 1) {
        const char * child_argv[5];
        apr_status_t rv;

        if (mc->pphrase_dialog_helper == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "NSSPassPhraseHelper is not set. It is required.");
            nss_die();
        }

        child_argv[0] = mc->pphrase_dialog_helper;
        child_argv[1] = fipsenabled ? "on" : "off";
        child_argv[2] = mc->pCertificateDatabase;
        child_argv[3] = mc->pDBPrefix;
        child_argv[4] = NULL;

        rv = apr_procattr_create(&mc->procattr, mc->pPool);

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "apr_procattr_create() failed APR err: %d.", rv);
            nss_die();
        }

        apr_procattr_io_set(mc->procattr, APR_PARENT_BLOCK, APR_PARENT_BLOCK,
                             APR_FULL_NONBLOCK);
        apr_procattr_error_check_set(mc->procattr, 1);

        /* the process inherits our environment, which should allow the
         * dynamic loader to find NSPR and NSS.
         */
        apr_procattr_cmdtype_set(mc->procattr, APR_PROGRAM_ENV);

        /* We've now spawned our helper process, the actual communication
         * with it occurs in nss_engine_pphrase.c.
         */
        rv = apr_proc_create(&mc->proc, child_argv[0], child_argv, NULL, mc->procattr, mc->pPool);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "apr_proc_create failed to launch %s APR err: %d.", child_argv[0], rv);
            nss_die();
        }
        /* Set a 30-second read/write timeout */
        apr_file_pipe_timeout_set(mc->proc.in, apr_time_from_sec(30));
        apr_file_pipe_timeout_set(mc->proc.out, apr_time_from_sec(30));
    }

    /* Initialize NSPR */
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 256);

    /* Set the PKCS #11 string for the internal token to a nicer name. */
    PK11_ConfigurePKCS11(NULL,NULL,NULL, INTERNAL_TOKEN_NAME, NULL, NULL,NULL,NULL,8,1);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, base_server,
        "Initializing SSL Session Cache of size %d. SSL2 timeout = %d, SSL3/TLS timeout = %d.", mc->session_cache_size, mc->session_cache_timeout, mc->ssl3_session_cache_timeout);
    ap_mpm_query(AP_MPMQ_MAX_THREADS, &threaded);
    if (!threaded)
        SSL_ConfigMPServerSIDCache(mc->session_cache_size, (PRUint32) mc->session_cache_timeout, (PRUint32) mc->ssl3_session_cache_timeout, NULL);
    else
        SSL_ConfigServerSessionIDCache(mc->session_cache_size, (PRUint32) mc->session_cache_timeout, (PRUint32) mc->ssl3_session_cache_timeout, NULL);

    /* Load our layer */
    nss_io_layer_init();

    if (mc->nInitCount == 1) {
        nss_init_SSLLibrary(base_server);
        /*
         *  initialize servers
         */
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, base_server,
                     "Init: Initializing (virtual) servers for SSL");

        for (s = base_server; s; s = s->next) {
            sc = mySrvConfig(s);
            /*
             * Either now skip this server when SSL is disabled for
             * it or give out some information about what we're
             * configuring.
             */

            /*
             * Read the server certificate and key
             */
            nss_init_ConfigureServer(s, p, ptemp, sc);
        }

        nss_init_ChildKill(base_server);
        nss_init_ModuleKill(base_server);
    }

    /*
     *  Announce mod_nss and SSL library in HTTP Server field
     *  as ``mod_nss/X.X.X NSS/X.X.X''
     */
    nss_add_version_components(p, base_server);

    return OK;
}

static void nss_init_ctx_socket(server_rec *s,
                                apr_pool_t *p,
                                apr_pool_t *ptemp,
                                modnss_ctx_t *mctx)
{
    /* Setup a socket in the context that will be used to model all
     * client connections. */
    mctx->model = nss_io_new_fd();
    mctx->model = SSL_ImportFD(NULL, mctx->model);

    if (SSL_OptionSet(mctx->model, SSL_SECURITY, PR_TRUE) != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "Unable to enable security.");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }

    if (SSL_OptionSet(mctx->model, SSL_HANDSHAKE_AS_SERVER, mctx->as_server)
            != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "Unable to set SSL server handshake mode.");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }
    if (SSL_OptionSet(mctx->model, SSL_HANDSHAKE_AS_CLIENT, !mctx->as_server)
            != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "Unable to set handshake as client");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }
    if (!mctx->as_server) {
        if ((SSL_OptionSet(mctx->model, SSL_NO_CACHE, PR_TRUE)) != SECSuccess) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                    "Unable to disable SSL client caching");
            nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
            nss_die();
        }
    }
}

static void nss_init_ctx_protocol(server_rec *s,
                                  apr_pool_t *p,
                                  apr_pool_t *ptemp,
                                  modnss_ctx_t *mctx)
{
    int ssl2, ssl3, tls;
    char *lprotocols = NULL;
    SECStatus stat;

    ssl2 = ssl3 = tls = 0;

    if (mctx->sc->fips) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
            "In FIPS mode, enabling TLSv1");
        tls = 1;
    } else {
        if (mctx->auth.protocols == NULL) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                "NSSProtocols not set; using: SSLv3 and TLSv1");
            ssl3 = tls = 1;
        } else {
            lprotocols = strdup(mctx->auth.protocols);
            ap_str_tolower(lprotocols);

            if (strstr(lprotocols, "all") != NULL) {
#ifdef WANT_SSL2
                ssl2 = ssl3 = tls = 1;
#else
                ssl3 = tls = 1;
#endif
            } else {
                if (strstr(lprotocols, "sslv2") != NULL) {
#ifdef WANT_SSL2
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "Enabling SSL2");
                    ssl2 = 1;
#else
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "SSL2 is not supported");
#endif
                }

                if (strstr(lprotocols, "sslv3") != NULL) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "Enabling SSL3");
                    ssl3 = 1;
                }

                if (strstr(lprotocols, "tlsv1") != NULL) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "Enabling TLS");
                    tls = 1;
                }
            }
            free(lprotocols);
        }
    }

    stat = SECSuccess;

    if (ssl2 == 1) {
        stat = SSL_OptionSet(mctx->model, SSL_ENABLE_SSL2, PR_TRUE);
    } else {
        stat = SSL_OptionSet(mctx->model, SSL_ENABLE_SSL2, PR_FALSE);
    }

    if (stat == SECSuccess) {
        if (ssl3 == 1) {
            stat = SSL_OptionSet(mctx->model, SSL_ENABLE_SSL3, PR_TRUE);
        } else {
            stat = SSL_OptionSet(mctx->model, SSL_ENABLE_SSL3, PR_FALSE);
        }
    }
    if (stat == SECSuccess) {
        if (tls == 1) {
            stat = SSL_OptionSet(mctx->model, SSL_ENABLE_TLS, PR_TRUE);
        } else {
            stat = SSL_OptionSet(mctx->model, SSL_ENABLE_TLS, PR_FALSE);
        }
    }

    if (stat != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "SSL protocol initialization failed.");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }

    mctx->ssl2 = ssl2;
    mctx->ssl3 = ssl3;
    mctx->tls = tls;
}

static void nss_init_ctx_session_cache(server_rec *s,
                                       apr_pool_t *p,
                                       apr_pool_t *ptemp,
                                       modnss_ctx_t *mctx)
{
}

static void nss_init_ctx_callbacks(server_rec *s,
                                   apr_pool_t *p,
                                   apr_pool_t *ptemp,
                                   modnss_ctx_t *mctx)
{
    if (SSL_AuthCertificateHook(mctx->model, nss_AuthCertificate, (void *)CERT_GetDefaultCertDB()) != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "SSL_AuthCertificateHook failed.");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }
    if (SSL_BadCertHook(mctx->model, (SSLBadCertHandler) ownBadCertHandler, NULL) != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "SSL_BadCertHook failed");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }
    if (SSL_HandshakeCallback(mctx->model, (SSLHandshakeCallback) ownHandshakeCallback, NULL) != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "SSL_HandshakeCallback failed");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }
    if (SSL_GetClientAuthDataHook(mctx->model, NSS_GetClientAuthData, (void *)mctx->nickname) != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "SSL_GetClientAuthDataHook failed");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }
}

static void nss_init_ctx_verify(server_rec *s,
                                apr_pool_t *p,
                                apr_pool_t *ptemp,
                                modnss_ctx_t *mctx)
{
    if (mctx->auth.verify_mode == SSL_CVERIFY_REQUIRE) {
        SSL_OptionSet(mctx->model, SSL_REQUEST_CERTIFICATE, PR_TRUE);
        SSL_OptionSet(mctx->model, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_ALWAYS);
    } else if (mctx->auth.verify_mode == SSL_CVERIFY_OPTIONAL) {
        SSL_OptionSet(mctx->model, SSL_REQUEST_CERTIFICATE, PR_TRUE);
        SSL_OptionSet(mctx->model, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NEVER);
    } else {
        SSL_OptionSet(mctx->model, SSL_REQUEST_CERTIFICATE, PR_FALSE);
        SSL_OptionSet(mctx->model, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NEVER);
    }
}

static int countciphers(PRBool cipher_state[ciphernum], int version) {
    int ciphercount = 0;
    int i;

    for (i = 0; i < ciphernum; i++)
    {
        if ((cipher_state[i] == PR_TRUE) &&
            (ciphers_def[i].version & version)) {
            ciphercount++;
        }
    }

    return ciphercount;
}

static void nss_init_ctx_cipher_suite(server_rec *s,
                                      apr_pool_t *p,
                                      apr_pool_t *ptemp,
                                      modnss_ctx_t *mctx)
{
    PRBool cipher_state[ciphernum];
    PRBool fips_state[ciphernum];
    const char *suite = mctx->auth.cipher_suite; 
    char * ciphers;
    char * fipsciphers = NULL;
    int i;
 
    /* 
     *  Configure SSL Cipher Suite
     */
    if (!suite) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "Required value NSSCipherSuite not set.");
        nss_die();
    }
    ciphers = strdup(suite);

#define CIPHERSIZE 2048

    if (mctx->sc->fips) {
        SSLCipherSuiteInfo suite;
        int i;
        int nfound = 0;

        fipsciphers = (char *)malloc(CIPHERSIZE);
        fipsciphers[0] = '\0';

        for (i=0; i<ciphernum;i++) {
            if (SSL_GetCipherSuiteInfo(ciphers_def[i].num,
                &suite, sizeof suite) == SECSuccess)
            {
                /* We could ignore the non-standard ciphers here but lets
                 * allow the user to choose.
                 */
                if (suite.isFIPS)
                {
                     strncat(fipsciphers, "+", CIPHERSIZE - strlen(fipsciphers));
                     strncat(fipsciphers, ciphers_def[i].name, CIPHERSIZE - strlen(fipsciphers));
                     strncat(fipsciphers, ",", CIPHERSIZE - strlen(fipsciphers));
                     nfound++;
                }
            }
        }

        if (nfound > 0) {
            fipsciphers[strlen(fipsciphers) - 1] = '\0'; /* remove last comma */
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "FIPS mode enabled, permitted SSL ciphers are: [%s]",
                 fipsciphers);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "Configuring permitted SSL ciphers [%s]",
                 suite);

    /* Disable all NSS supported cipher suites. This is to prevent any new
     * NSS cipher suites from getting automatically and unintentionally
     * enabled as a result of the NSS_SetDomesticPolicy() call. This way,
     * only the ciphers explicitly specified in the server configuration can
     * ever be enabled.
     */

    for (i = 0; i < SSL_NumImplementedCiphers; i++)
    {
        SSL_CipherPrefSet(mctx->model, SSL_ImplementedCiphers[i], SSL_NOT_ALLOWED);
    }

    /* initialize all known ciphers to false */
    for (i=0; i<ciphernum; i++)
    {
        cipher_state[i] = PR_FALSE;
        fips_state[i] = PR_FALSE;
    }

    if (nss_parse_ciphers(s, ciphers, cipher_state) == -1) {
        nss_die();
    }

    if (mctx->sc->fips) {
        if (nss_parse_ciphers(s, fipsciphers, fips_state) == -1) {
            nss_die();
        }
    }

    free(ciphers);
    free(fipsciphers);

    /* If FIPS is enabled, see if any non-FIPS ciphers were selected */
    if (mctx->sc->fips) {
        for (i=0; i<ciphernum; i++) {
            if (cipher_state[i] == PR_TRUE && fips_state[i] == PR_FALSE) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                    "Cipher %s is enabled but this is not a FIPS cipher, disabling.", ciphers_def[i].name);
                cipher_state[i] = PR_FALSE;
            }
        }
    }

    /* See if any ciphers have been enabled for a given protocol */
    if (mctx->ssl2 && countciphers(cipher_state, SSL2) == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "SSL2 is enabled but no SSL2 ciphers are enabled.");
        nss_die();
    }

    if (mctx->ssl3 && countciphers(cipher_state, SSL3) == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "SSL3 is enabled but no SSL3 ciphers are enabled.");
        nss_die();
    }

    if (mctx->tls && countciphers(cipher_state, TLS) == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "TLS is enabled but no TLS ciphers are enabled.");
        nss_die();
    }

    /* Finally actually enable the selected ciphers */
    for (i=0; i<ciphernum;i++) {
        SSL_CipherPrefSet(mctx->model, ciphers_def[i].num, cipher_state[i]);
    }
}

static void nss_init_server_check(server_rec *s,
                                 apr_pool_t *p,
                                 apr_pool_t *ptemp,
                                 modnss_ctx_t *mctx)
{
#ifdef NSS_ENABLE_ECC
    if (mctx->servercert != NULL || mctx->eccservercert != NULL) {
#else
    if (mctx->servercert != NULL) {
#endif
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "Illegal attempt to re-initialise SSL for server "
                "(theoretically shouldn't happen!)");
        nss_die();
    }
}

static void nss_init_ctx(server_rec *s,
                         apr_pool_t *p,
                         apr_pool_t *ptemp,
                         modnss_ctx_t *mctx) 
{

    nss_init_ctx_socket(s, p, ptemp, mctx);

    nss_init_ctx_protocol(s, p, ptemp, mctx);
    
    nss_init_ctx_session_cache(s, p, ptemp, mctx);
    
    nss_init_ctx_callbacks(s, p, ptemp, mctx);
    
    nss_init_ctx_verify(s, p, ptemp, mctx);

    nss_init_ctx_cipher_suite(s, p, ptemp, mctx);
}

static void nss_init_certificate(server_rec *s, const char *nickname,
                                 CERTCertificate **servercert,
                                 SECKEYPrivateKey **serverkey,
                                 SSLKEAType *KEAtype,
                                 PRFileDesc *model,
                                 int enforce)
{
    SECCertTimeValidity certtimestatus;
    SECStatus secstatus;

    PK11SlotInfo* slot = NULL;
 
    if (nickname == NULL) {
        return;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
         "Using nickname %s.", nickname);

    *servercert = FindServerCertFromNickname(nickname);

    /* Verify the certificate chain. */
    if (*servercert != NULL) {
        SECCertificateUsage usage = certificateUsageSSLServer;

        if (CERT_VerifyCertificateNow(CERT_GetDefaultCertDB(), *servercert, PR_TRUE, usage, NULL, NULL) != SECSuccess)  {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "Certificate not verified: '%s'", nickname);
            nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
            if (enforce) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                    "Unable to verify certificate '%s'. Add \"NSSEnforceValidCerts off\" to nss.conf so the server can start until the problem can be resolved.", nickname);
                nss_die();
            }
        }
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "Certificate not found: '%s'", nickname);
        nss_die();
    }

    if (strchr(nickname, ':'))
    {
        char* token = strdup(nickname); 
        char* colon = strchr(token, ':');
        if (colon) {
            *colon = 0;
            slot = PK11_FindSlotByName(token);
            if (!slot) {
                /* 
                 * Slot not found. This should never happen because we
                 * already found the cert.
                 */
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                    "Slot not found");
                nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
                free(token);
                nss_die();
            }
        }
        free(token);
    }
    else {
        slot = PK11_GetInternalKeySlot();
    }

    *serverkey = PK11_FindPrivateKeyFromCert(slot, *servercert, NULL);

    PK11_FreeSlot(slot);

    if (*serverkey == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "Key not found for: '%s'", nickname);
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }

    *KEAtype = NSS_FindCertKEAType(*servercert);

    /*
     * Check for certs that are expired or not yet valid and WARN about it
     * no need to refuse working - the client gets a warning, but can work
     * with the server we could also verify if the certificate is made out
     * for the correct hostname but that would require a reverse DNS lookup
     * for every virtual server - too expensive?
     */

    certtimestatus = CERT_CheckCertValidTimes(*servercert, PR_Now(), PR_FALSE);
    switch (certtimestatus)
    {
        case secCertTimeValid:
            /* ok */
            break;
        case secCertTimeExpired:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "Server certificate is expired: '%s'", nickname);
            break;
        case secCertTimeNotValidYet:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "Certificate is not valid yet '%s'", nickname);
        default:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "Unhandled Certificate time type %d for: '%s'", certtimestatus, nickname);
            break;
    }

    secstatus = SSL_ConfigSecureServer(model, *servercert, *serverkey, *KEAtype);
    if (secstatus != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "SSL error configuring server: '%s'", nickname);
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }
}


static void nss_init_server_certs(server_rec *s,
                                  apr_pool_t *p,
                                  apr_pool_t *ptemp,
                                  modnss_ctx_t *mctx)
{
    SECStatus secstatus;

    /*
     * Get own certificate and private key.
     */
    if (mctx->as_server) {
#ifdef NSS_ENABLE_ECC
        if (mctx->nickname == NULL && mctx->eccnickname == NULL)
#else
        if (mctx->nickname == NULL)
#endif
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "No certificate nickname provided.");
            nss_die();
        }

        nss_init_certificate(s, mctx->nickname, &mctx->servercert,
                             &mctx->serverkey, &mctx->serverKEAType,
                             mctx->model, mctx->enforce);
#ifdef NSS_ENABLE_ECC
        nss_init_certificate(s, mctx->eccnickname, &mctx->eccservercert,
                             &mctx->eccserverkey, &mctx->eccserverKEAType,
                             mctx->model, mctx->enforce);
#endif
    }

    secstatus = (SECStatus)SSL_SetPKCS11PinArg(mctx->model, NULL);
    if (secstatus != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "Error setting PKCS11 pin argument: '%s'", mctx->nickname);
        nss_die();
    }
    
    secstatus = (SECStatus)SSL_HandshakeCallback(mctx->model, (SSLHandshakeCallback)NSSHandshakeCallback, NULL);
    if (secstatus != SECSuccess)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "SSL error configuring handshake callback: '%s'", mctx->nickname);
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }
}

static void nss_init_proxy_ctx(server_rec *s,
                                apr_pool_t *p,
                                apr_pool_t *ptemp,
                                SSLSrvConfigRec *sc)
{
    nss_init_ctx(s, p, ptemp, sc->proxy);

    nss_init_server_certs(s, p, ptemp, sc->proxy);
}

static void nss_init_server_ctx(server_rec *s,
                                apr_pool_t *p,
                                apr_pool_t *ptemp,
                                SSLSrvConfigRec *sc)
{
    nss_init_server_check(s, p, ptemp, sc->server);

    nss_init_ctx(s, p, ptemp, sc->server);

    nss_init_server_certs(s, p, ptemp, sc->server);
}

/*
 * Configure a particular server
 */
void nss_init_ConfigureServer(server_rec *s,
                              apr_pool_t *p,
                              apr_pool_t *ptemp,
                              SSLSrvConfigRec *sc)
{
    if (sc->enabled == TRUE) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "Configuring server for SSL protocol");
        nss_init_server_ctx(s, p, ptemp, sc);
    }

    if (sc->proxy_enabled == TRUE) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "Enabling proxy.");
        nss_init_proxy_ctx(s, p, ptemp, sc);
    }
}

void nss_init_Child(apr_pool_t *p, server_rec *base_server)
{
    SSLModConfigRec *mc = myModConfig(base_server);
    SSLSrvConfigRec *sc;
    server_rec *s;

    mc->pid = getpid(); /* only call getpid() once per-process */

    if (SSL_InheritMPServerSIDCache(NULL) != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
             "SSL_InheritMPServerSIDCache failed");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, NULL);
    }

    nss_init_SSLLibrary(base_server);

    /* Configure all virtual servers */
    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);
        if (sc->server->servercert == NULL && NSS_IsInitialized())
            nss_init_ConfigureServer(s, p, mc->ptemp, sc);
    }

    /* 
     * Let us cleanup on restarts and exits
     */
    apr_pool_cleanup_register(p, base_server,
                              nss_init_ChildKill,
                              apr_pool_cleanup_null);
}

apr_status_t nss_init_ModuleKill(void *data)
{
    server_rec *base_server = (server_rec *)data;

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, base_server,
        "Shutting down SSL Session ID Cache");

    SSL_ShutdownServerSessionIDCache();

    /* NSS_Shutdown() gets called in nss_init_ChildKill */
    return APR_SUCCESS;
}

apr_status_t nss_init_ChildKill(void *data)
{
    SSLSrvConfigRec *sc;
    server_rec *base_server = (server_rec *)data;
    server_rec *s;
    int shutdown = 0;

    /* Clear any client-side session cache data */
    SSL_ClearSessionCache();

    /*
     * Free the non-pool allocated structures
     * in the per-server configurations
     */
    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);

        if (sc->enabled == TRUE) {
            if (sc->server->nickname) {
                CERT_DestroyCertificate(sc->server->servercert);
                SECKEY_DestroyPrivateKey(sc->server->serverkey);
            }
#ifdef NSS_ENABLE_ECC
            if (sc->server->eccnickname) {
                CERT_DestroyCertificate(sc->server->eccservercert);
                SECKEY_DestroyPrivateKey(sc->server->eccserverkey);
            }
#endif

            /* Closing this implicitly cleans up the copy of the certificates
             * and keys associated with any SSL socket */
            if (sc->server->model)
                PR_Close(sc->server->model);

            shutdown = 1;
        }
        if (sc->proxy_enabled) {
            if (sc->proxy->servercert != NULL) {
                CERT_DestroyCertificate(sc->proxy->servercert);
                SECKEY_DestroyPrivateKey(sc->proxy->serverkey);
            }

            /* Closing this implicitly cleans up the copy of the certificates
             * and keys associated with any SSL socket */
            if (sc->proxy->model)
                PR_Close(sc->proxy->model);

            shutdown = 1;
        }
    }

    if (shutdown) {
        if (CERT_DisableOCSPDefaultResponder(CERT_GetDefaultCertDB())
            != SECSuccess) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                 "Turning off the OCSP default responder failed.");
            nss_log_nss_error(APLOG_MARK, APLOG_ERR, NULL);
        }

        NSS_Shutdown();
    }

    return APR_SUCCESS;
}

/*
 * This callback is used when the incoming cert is not valid.
 * It should return SECSuccess to accept the cert anyway, SECFailure
 * to reject. In this case we always reject.
 */
SECStatus ownBadCertHandler(void *arg, PRFileDesc * socket)
{
    PRErrorCode err = PR_GetError();

    switch (err) {
        default:
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                "Bad remote server certificate: %d", err);
            nss_log_nss_error(APLOG_MARK, APLOG_ERR, NULL);
            return SECFailure;
            break;
    }
}

/*
 * Called by SSL to inform application that the handshake is
 * complete. This function is mostly used on the server side of an SSL
 * connection, although it is provided for a client as well.
 * We don't do anything special.
 */
SECStatus ownHandshakeCallback(PRFileDesc * socket, void *arg)
{
    return SECSuccess;
}

/*
 * Duplicated, non-exported function from NSS that compares 2 certificate
 * times.
 */
static PRBool
cert_IsNewer(CERTCertificate *certa, CERTCertificate *certb)
{ 
    PRTime notBeforeA, notAfterA, notBeforeB, notAfterB, now;
    SECStatus rv;
    PRBool newerbefore, newerafter;

    newerbefore = newerafter = PR_FALSE;

    rv = CERT_GetCertTimes(certa, &notBeforeA, &notAfterA);
    if ( rv != SECSuccess ) {
        return(PR_FALSE);
    }

    rv = CERT_GetCertTimes(certb, &notBeforeB, &notAfterB);
    if ( rv != SECSuccess ) {
        return(PR_TRUE);
    }

    if ( LL_CMP(notBeforeA, >, notBeforeB) ) {
        newerbefore = PR_TRUE;
    }

    if ( LL_CMP(notAfterA, >, notAfterB) ) {
        newerafter = PR_TRUE;
    }

    if ( newerbefore && newerafter ) {
        return(PR_TRUE);
    }

    if ( ( !newerbefore ) && ( !newerafter ) ) {
        return(PR_FALSE);
    }

    /* get current UTC time */
    now = PR_Now();

    if ( newerbefore ) {
        /* cert A was issued after cert B, but expires sooner */
        /* if A is expired, then pick B */
        if ( LL_CMP(notAfterA, <, now ) ) {
            return(PR_FALSE);
        }
        return(PR_TRUE);
    } else {
        /* cert B was issued after cert A, but expires sooner */
        /* if B is expired, then pick A */
        if ( LL_CMP(notAfterB, <, now ) ) {
            return(PR_TRUE);
        }
        return(PR_FALSE);
    }
}

/*
 * Given a nickname, find the "best" certificate available for that
 * certificate (for the case of multiple CN's with different usages, a
 * renewed cert that is not yet valid, etc). The best is defined as the
 * newest, valid server certificate.
 */
static CERTCertificate*
FindServerCertFromNickname(const char* name)
{
    CERTCertList* clist;
    CERTCertificate* bestcert = NULL;

    CERTCertListNode *cln;
    PRUint32 bestCertMatchedUsage = 0;
    PRBool bestCertIsValid = PR_FALSE;

    if (name == NULL)
        return NULL;

    clist = PK11_ListCerts(PK11CertListUser, NULL);

    for (cln = CERT_LIST_HEAD(clist); !CERT_LIST_END(cln,clist);
        cln = CERT_LIST_NEXT(cln)) {
        CERTCertificate* cert = cln->cert;
        const char* nickname = (const char*) cln->appData;
        if (!nickname) {
            nickname = cert->nickname;
        }
        if (strcmp(name, nickname) == 0) {
            PRUint32 matchedUsage = 0;
            PRBool isValid = PR_FALSE;
            PRBool swapcert = PR_FALSE;
            /* We still need to check key usage. Dual-key certs appear
             * as 2 certs in the list with different usages. We want to pick
             * the "best" one, preferrably the one with certUsageSSLServer.
             * Otherwise just return the cert if the nickname matches.
             */
            if (CERT_CheckCertUsage(cert, certUsageSSLServer) == SECSuccess) {
                matchedUsage = 2; 
            } else {
                if (CERT_CheckCertUsage(cert, certUsageEmailRecipient) == SECSuccess) 
                {
                    matchedUsage = 1; 
                }
            }

            if (secCertTimeValid == CERT_CheckCertValidTimes(cert, PR_Now(), PR_FALSE))
            {
                /* This is a valid certificate. */
                isValid = PR_TRUE;
            }
            if (!bestcert) {
                /* We didn't have a cert picked yet, automatically choose this
                 * one.
                 */
                swapcert = PR_TRUE;
            } else {
                if (matchedUsage > bestCertMatchedUsage) {
                    /* The cert previously picked didn't have the correct
                     * usage, but this one does. Choose this one.
                     */
                    swapcert = PR_TRUE;
                } else {
                    if ( (bestCertMatchedUsage == matchedUsage) &&
                    (((PR_FALSE == bestCertIsValid) && (PR_TRUE == isValid)) ||
                    ((PR_TRUE == bestCertIsValid == isValid) && (PR_TRUE == cert_IsNewer(cert, bestcert))))) {
                        /* The cert previously picked was invalid but this one
                         * is. Or they were both valid but this one is newer.
                         */
                        swapcert = PR_TRUE;
                    }
                }
            }

            if (swapcert == PR_TRUE)
            {
                bestcert = cert;
                bestCertMatchedUsage = matchedUsage;
                bestCertIsValid = isValid;
            }
        }
    }
    if (bestcert) {
        bestcert = CERT_DupCertificate(bestcert);
    }
    if (clist) {
        CERT_DestroyCertList(clist);
    }
    return bestcert;
}

/*
 * Executed automatically when the SSL handshake is completed.
 * We don't do anything special here.
 */
SECStatus NSSHandshakeCallback(PRFileDesc *socket, void *arg)
{
    return SECSuccess;
}

int nss_parse_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum])
{
    char * cipher;
    PRBool found, active;
    int i;

    cipher = ciphers;

    while (ciphers && (strlen(ciphers)))
    {
        while ((*cipher) && (isspace(*cipher)))
           ++cipher;

        switch(*cipher++)
        {
            case '+':
                active = PR_TRUE;
                break;
            case '-':
                active = PR_FALSE;
                break;
            default:
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "invalid cipher string %s. Format is +cipher1,-cipher2...", cipher - 1);
            return -1;
        }

        if ((ciphers = strchr(cipher, ','))) {
            *ciphers++ = '\0';
        }

        found = PR_FALSE;

        for (i = 0; i < ciphernum; i++)
        {
            if (!strcasecmp(cipher, ciphers_def[i].name)) {
                cipher_list[i] = active;
                found = PR_TRUE;
                break;
            }
        }

        if (found == PR_FALSE) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "Unknown cipher %s", cipher);
        }

        if (ciphers) {
            cipher = ciphers;
        }
    }

    return 0;
}
