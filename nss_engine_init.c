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
#include "nss_engine_cipher.h"
#include "apr_thread_proc.h"
#include "apr_strings.h"
#include "mpm_common.h"
#if AP_SERVER_MINORVERSION_NUMBER <= 2
#include "ap_mpm.h"
#endif
#include "secmod.h"
#include "sslerr.h"
#include "pk11func.h"
#include "ocsp.h"
#include "keyhi.h"
#include "cert.h"

static SECStatus ownBadCertHandler(void *arg, PRFileDesc * socket);
static SECStatus ownHandshakeCallback(PRFileDesc * socket, void *arg);
static SECStatus NSSHandshakeCallback(PRFileDesc *socket, void *arg);
static CERTCertificate* FindServerCertFromNickname(const char* name, const CERTCertList* clist);
SECStatus nss_AuthCertificate(void *arg, PRFileDesc *socket, PRBool checksig, PRBool isServer);
PRInt32 nssSSLSNISocketConfig(PRFileDesc *fd, const SECItem *sniNameArr, PRUint32 sniNameArrSize, void *arg);

/*
 * Global variables defined in this file.
 */
char* INTERNAL_TOKEN_NAME = "internal                         ";

extern cipher_properties ciphers_def[];

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
static void nss_init_SSLLibrary(server_rec *base_server, apr_pool_t *p)
{
    SECStatus rv;
    SSLModConfigRec *mc = myModConfig(base_server);
    SSLSrvConfigRec *sc;
    char cwd[PATH_MAX];
    server_rec *s;
    int fipsenabled = FALSE;
    int ocspenabled = FALSE;
    int ocspdefault = FALSE;
    int snienabled = FALSE;
    char *dbdir = NULL;
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

        if (sc->sni == TRUE) {
            snienabled = TRUE;
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
    if (strncasecmp(mc->pCertificateDatabase, "sql:", 4) == 0)
        dbdir = (char *)mc->pCertificateDatabase + 4;
    else
        dbdir = (char *)mc->pCertificateDatabase;
    if (chdir(dbdir) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
            "Unable to change directory to %s", mc->pCertificateDatabase);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
            "Does the directory exist and do the permissions allow access?");
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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
            "Does the directory exist and do the permissions allow access?");
        if (mc->nInitCount == 1)
            nss_die();
        else
            return;
    }

    /* Assuming everything is ok so far, check the cert database password(s). */
    if (rv != SECSuccess) {
        apr_finfo_t finfo;
        char keypath[1024];
        int rv;
        uid_t user_id;
        gid_t gid;

        user_id = ap_uname2id(mc->user);
        gid = getegid();

        NSS_Shutdown();
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
            "NSS_Initialize failed. Certificate database: %s.", mc->pCertificateDatabase != NULL ? mc->pCertificateDatabase : "not set in configuration");

        nss_log_nss_error(APLOG_MARK, APLOG_ERR, base_server);
        apr_snprintf(keypath, 1024, "%s/key3.db", mc->pCertificateDatabase);
        if ((rv = apr_stat(&finfo, keypath, APR_FINFO_PROT | APR_FINFO_OWNER,
             p)) == APR_SUCCESS) {
            if (((user_id == finfo.user) &&
                    (!(finfo.protection & APR_FPROT_UREAD))) ||
                ((gid == finfo.group) &&
                    (!(finfo.protection & APR_FPROT_GREAD))) ||
                (!(finfo.protection & APR_FPROT_WREAD))
               )
            {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
                    "Server user lacks read access to NSS database.");
            }
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
                "Does the NSS database exist?");
        }
        nss_die();
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

    if (snienabled) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server,
            "SNI is enabled");
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base_server,
            "SNI is disabled");
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
    struct semid_ds status;
    char *split_vhost_id = NULL;
    char *last1;

    mc->nInitCount++;

    /*
     * Let us cleanup on restarts and exists
     */
    apr_pool_cleanup_register(p, base_server,
                              nss_init_ModuleKill,
                              apr_pool_cleanup_null);

    mc->ptemp = ptemp;

    /*
     * Any init round fixes the global config
     */
    nss_config_global_create(base_server); /* just to avoid problems */

    /*
     * Fix up any global settings that aren't in the configuration
     */
    if (mc->session_cache_timeout != UNSET) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, base_server,
            "NSSSessionCacheTimeout is deprecated. Ignoring.");

        /* We still need to pass in a legal value to
         * SSL_ConfigMPServerSIDCache() and SSL_ConfigServerSessionIDCache()
         */
        mc->session_cache_timeout = 0; /* use NSS default */
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

        if (sc->sni && sc->server->nickname != NULL && sc->vhost_id != NULL) {
            split_vhost_id = apr_strtok((char *)sc->vhost_id, ":", &last1);
            ap_str_tolower(split_vhost_id);
            addHashVhostNick(split_vhost_id, (char *)sc->server->nickname);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "SNI: %s -> %s", split_vhost_id, (char *)sc->server->nickname);
	}

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

    /* The first pass through this function will create the semaphore that
     * will be used to lock the pipe. The user is still root at that point
     * so for any later calls the semaphore ops will fail with permission
     * errors. So switch the user to the Apache user.
     */
    if (mc->semid) {
        uid_t user_id;

        user_id = ap_uname2id(mc->user);
        semctl(mc->semid, 0, IPC_STAT, &status);
        status.sem_perm.uid = user_id;
        semctl(mc->semid,0,IPC_SET,&status);
    }

    /* Do we need to fire up our password helper? */
    if (mc->nInitCount == 1) {
        const char * child_argv[6];
        apr_status_t rv;
        struct sembuf sb;
        char sembuf[32];

        if (mc->pphrase_dialog_helper == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "NSSPassPhraseHelper is not set. It is required.");
            nss_die();
        }

        mc->semid = semget(IPC_PRIVATE, 1, IPC_CREAT | IPC_EXCL | 0600);
        if (mc->semid == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "Unable to obtain semaphore.");
            nss_die();
        }

        /* Initialize the semaphore */
        sb.sem_num = 0;
        sb.sem_op = 1;
        sb.sem_flg = 0;
        if ((semop(mc->semid, &sb, 1)) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "Unable to initialize semaphore.");
            nss_die();
        }

        PR_snprintf(sembuf, 32, "%d", mc->semid);

        child_argv[0] = mc->pphrase_dialog_helper;
        child_argv[1] = sembuf;
        child_argv[2] = fipsenabled ? "on" : "off";
        child_argv[3] = mc->pCertificateDatabase;
        child_argv[4] = mc->pDBPrefix;
        child_argv[5] = NULL;

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
        "Initializing SSL Session Cache of size %d. SSL3/TLS timeout = %d.", mc->session_cache_size, mc->ssl3_session_cache_timeout);
    ap_mpm_query(AP_MPMQ_MAX_THREADS, &threaded);
    if (!threaded)
        SSL_ConfigMPServerSIDCache(mc->session_cache_size, (PRUint32) mc->session_cache_timeout, (PRUint32) mc->ssl3_session_cache_timeout, NULL);
    else
        SSL_ConfigServerSessionIDCache(mc->session_cache_size, (PRUint32) mc->session_cache_timeout, (PRUint32) mc->ssl3_session_cache_timeout, NULL);

    /* Load our layer */
    nss_io_layer_init();

    if (mc->nInitCount == 1) {
        nss_init_SSLLibrary(base_server, mc->pPool);
        /*
         *  initialize servers
         */
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, base_server,
                     "Init: Initializing (virtual) servers for SSL");

        CERTCertList* clist = PK11_ListCerts(PK11CertListUserUnique, NULL);

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
            nss_init_ConfigureServer(s, p, ptemp, sc, clist);
        }

        if (clist) {
            CERT_DestroyCertList(clist);
        }
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
#ifdef SSL_ENABLE_RENEGOTIATION
    if (SSL_OptionSet(mctx->model, SSL_ENABLE_RENEGOTIATION,
            mctx->enablerenegotiation ?
              SSL_RENEGOTIATE_REQUIRES_XTN : SSL_RENEGOTIATE_NEVER
              ) != SECSuccess) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                    "Unable to set SSL renegotiation");
            nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
            nss_die();
    }
    if (SSL_OptionSet(mctx->model, SSL_REQUIRE_SAFE_NEGOTIATION,
            mctx->requiresafenegotiation) != SECSuccess) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                    "Unable to set SSL safe negotiation");
            nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
            nss_die();
    }
#endif
}

static void nss_init_ctx_protocol(server_rec *s,
                                  apr_pool_t *p,
                                  apr_pool_t *ptemp,
                                  modnss_ctx_t *mctx)
{
    int ssl3, tls, tls1_1, tls1_2;
    char *protocol_marker = NULL;
    char *lprotocols = NULL;
    SECStatus stat;
    SSLVersionRange enabledVersions;

    ssl3 = tls = tls1_1 = tls1_2 = 0;

    /*
     * Since this routine will be invoked individually for every thread
     * associated with each 'server' object as well as for every thread
     * associated with each 'proxy' object, identify the protocol marker
     * ('NSSProtocol' for 'server' versus 'NSSProxyProtocol' for 'proxy')
     * via each thread's object type and apply this useful information to
     * all log messages.
     */
    if (mctx == mctx->sc->server) {
        protocol_marker = "NSSProtocol";
    } else if (mctx == mctx->sc->proxy) {
        protocol_marker = "NSSProxyProtocol";
    }

    if (mctx->sc->fips) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
            "In FIPS mode ignoring %s list, enabling TLSv1.0, TLSv1.1 and TLSv1.2",
            protocol_marker);
        tls = tls1_1 = tls1_2 = 1;
    } else {
        if (mctx->auth.protocols == NULL) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                "%s value not set; using: TLSv1.0, TLSv1.1 and TLSv1.2",
                protocol_marker);
            tls = tls1_1 = tls1_2 = 1;
        } else {
            lprotocols = strdup(mctx->auth.protocols);
            ap_str_tolower(lprotocols);

            if (strstr(lprotocols, "all") != NULL) {
                ssl3 = tls = tls1_1 = tls1_2 = 1;
            } else {
                char *protocol_list = NULL;
                char *saveptr = NULL;
                char *token = NULL;

                for (protocol_list = lprotocols; ; protocol_list = NULL) {
                    token = strtok_r(protocol_list, ",", &saveptr);
                    if (token == NULL) {
                        break;
                    } else if (strcmp(token, "sslv2") == 0) {
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                                     "%s:  SSL2 is not supported",
                                     protocol_marker);
                    } else if (strcmp(token, "sslv3") == 0) {
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                                     "%s:  Enabling SSL3",
                                     protocol_marker);
                        ssl3 = 1;
                    } else if (strcmp(token, "tlsv1") == 0) {
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                                     "%s:  Enabling TLSv1.0 via TLSv1",
                                     protocol_marker);
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                                     "%s:  The 'TLSv1' protocol name has been deprecated; please change 'TLSv1' to 'TLSv1.0'.",
                                     protocol_marker);
                        tls = 1;
                    } else if (strcmp(token, "tlsv1.0") == 0) {
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                                     "%s:  Enabling TLSv1.0",
                                     protocol_marker);
                        tls = 1;
                    } else if (strcmp(token, "tlsv1.1") == 0) {
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                                     "%s:  Enabling TLSv1.1",
                                     protocol_marker);
                        tls1_1 = 1;
                    } else if (strcmp(token, "tlsv1.2") == 0) {
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                                     "%s:  Enabling TLSv1.2",
                                     protocol_marker);
                        tls1_2 = 1;
                    } else {
                        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                                     "%s:  Unknown protocol '%s' not supported",
                                     protocol_marker, token);
                    }
                }
            }
            free(lprotocols);
        }
    }

    stat = SECSuccess;

    stat = SSL_OptionSet(mctx->model, SSL_ENABLE_SSL2, PR_FALSE);

    /* Set protocol version ranges:
     *
     *     (1) Set the minimum protocol accepted
     *     (2) Set the maximum protocol accepted
     *     (3) Protocol ranges extend from maximum down to minimum protocol
     *     (4) All protocol ranges are completely inclusive;
     *         no protocol in the middle of a range may be excluded
     *     (5) NSS automatically negotiates the use of the strongest protocol
     *         for a connection starting with the maximum specified protocol
     *         and downgrading as necessary to the minimum specified protocol
     *
     * For example, if SSL 3.0 is chosen as the minimum protocol, and
     * TLS 1.1 is chosen as the maximum protocol, SSL 3.0, TLS 1.0, and
     * TLS 1.1 will all be accepted as protocols, as TLS 1.0 will not and
     * cannot be excluded from this range. NSS will automatically negotiate
     * to utilize the strongest acceptable protocol for a connection starting
     * with the maximum specified protocol and downgrading as necessary to the
     * minimum specified protocol (TLS 1.2 -> TLS 1.1 -> TLS 1.0 -> SSL 3.0).
     */
    if (stat == SECSuccess) {
        /* Set minimum protocol version (lowest -> highest)
         *
         *     SSL 3.0 -> TLS 1.0 -> TLS 1.1 -> TLS 1.2
         */
        if (ssl3 == 1) {
            enabledVersions.min = SSL_LIBRARY_VERSION_3_0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s:  [SSL 3.0] (minimum)",
                         protocol_marker);
        } else if (tls == 1) {
            enabledVersions.min = SSL_LIBRARY_VERSION_TLS_1_0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s:  [TLS 1.0] (minimum)",
                         protocol_marker);
        } else if (tls1_1 == 1) {
            enabledVersions.min = SSL_LIBRARY_VERSION_TLS_1_1;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s:  [TLS 1.1] (minimum)",
                         protocol_marker);
        } else if (tls1_2 == 1) {
            enabledVersions.min = SSL_LIBRARY_VERSION_TLS_1_2;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s:  [TLS 1.2] (minimum)",
                         protocol_marker);
        } else {
            /* Set default minimum protocol version to SSL 3.0 */
            enabledVersions.min = SSL_LIBRARY_VERSION_3_0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s:  [SSL 3.0] (default minimum)",
                         protocol_marker);
        }

        /* Set maximum protocol version (highest -> lowest)
         *
         *     TLS 1.2 -> TLS 1.1 -> TLS 1.0 -> SSL 3.0
         */
        if (tls1_2 == 1) {
            enabledVersions.max = SSL_LIBRARY_VERSION_TLS_1_2;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s:  [TLS 1.2] (maximum)",
                         protocol_marker);
        } else if (tls1_1 == 1) {
            enabledVersions.max = SSL_LIBRARY_VERSION_TLS_1_1;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s:  [TLS 1.1] (maximum)",
                         protocol_marker);
        } else if (tls == 1) {
            enabledVersions.max = SSL_LIBRARY_VERSION_TLS_1_0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s:  [TLS 1.0] (maximum)",
                         protocol_marker);
        } else if (ssl3 == 1) {
            enabledVersions.max = SSL_LIBRARY_VERSION_3_0;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s:  [SSL 3.0] (maximum)",
                         protocol_marker);
        } else {
            /* Set default maximum protocol version to TLS 1.2 */
            enabledVersions.max = SSL_LIBRARY_VERSION_TLS_1_2;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "%s:  [TLS 1.2] (default maximum)",
                         protocol_marker);
        }

        stat = SSL_VersionRangeSet(mctx->model, &enabledVersions);
    }

    if (stat != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "%s:  SSL/TLS protocol initialization failed.",
                protocol_marker);
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }

    mctx->ssl3 = ssl3;
    mctx->tls = tls || tls1_1 || tls1_2;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
        "%sabling TLS Session Tickets", mctx->sc->session_tickets == PR_TRUE ? "En" : "Dis");
    if (SSL_OptionSet(mctx->model, SSL_ENABLE_SESSION_TICKETS,
        mctx->sc->session_tickets) != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "Unable to configure TLS Session Tickets");
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }
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

static void nss_init_ctx_cipher_suite(server_rec *s,
                                      apr_pool_t *p,
                                      apr_pool_t *ptemp,
                                      modnss_ctx_t *mctx)
{
    PRBool cipher_state[ciphernum];
    PRBool fips_state[ciphernum];
    const char *suite = mctx->auth.cipher_suite;
    char * object_type = NULL;
    char * cipher_suite_marker = NULL;
    char * ciphers;
    char * fipsciphers = NULL;
    int i;

    /*
     *  Configure SSL Cipher Suite
     */
    if (!suite) {
        /*
         * Since this is a 'fatal' error, regardless of whether this
         * particular invocation is from a 'server' object or a 'proxy'
         * object, issue all error message(s) as appropriate.
         */
        if ((mctx->sc->enabled == TRUE) &&
            (mctx->sc->server) &&
            (!mctx->sc->server->auth.cipher_suite)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "NSSEngine on; required value NSSCipherSuite not set.");
        }

        if ((mctx->sc->proxy_enabled == TRUE) &&
            (mctx->sc->proxy) &&
            (!mctx->sc->proxy->auth.cipher_suite)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "NSSProxyEngine on; required value NSSProxyCipherSuite not set.");
        }

        nss_die();
    }

    /*
     * Since this routine will be invoked individually for every thread
     * associated with each 'server' object as well as for every thread
     * associated with each 'proxy' object, identify the cipher suite markers
     * ('NSSCipherSuite' for 'server' versus 'NSSProxyCipherSuite' for 'proxy')
     * via each thread's object type and apply this useful information to
     * all log messages.
     */
    if (mctx == mctx->sc->server) {
        object_type = "server";
        cipher_suite_marker = "NSSCipherSuite";
    } else if (mctx == mctx->sc->proxy) {
        object_type = "proxy";
        cipher_suite_marker = "NSSProxyCipherSuite";
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
            "FIPS mode enabled on this %s, permitted SSL ciphers are: [%s]",
            object_type, fipsciphers);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "%s:  Configuring permitted SSL ciphers [%s]",
                 cipher_suite_marker, suite);

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
                    "Cipher %s is enabled for this %s, but this is not a FIPS cipher, disabling.", ciphers_def[i].name, object_type);
                cipher_state[i] = PR_FALSE;
            }
        }
    }

    if (mctx->ssl3 && countciphers(cipher_state, SSLV3) == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "%s:  SSL3 is enabled but no SSL3 ciphers are enabled.",
            cipher_suite_marker);
        nss_die();
    }

    if (mctx->tls && countciphers(cipher_state, TLSV1|TLSV1_2) == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "%s:  TLS is enabled but no TLS ciphers are enabled.",
            cipher_suite_marker);
        nss_die();
    }

    /* Finally actually enable the selected ciphers */
    for (i=0; i<ciphernum;i++) {
        SSL_CipherPrefSet(mctx->model, ciphers_def[i].num, cipher_state[i] == 1 ? PR_TRUE : PR_FALSE);
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
                                 int enforce,
                                 int sni,
                                 const CERTCertList* clist)
{
    SECCertTimeValidity certtimestatus;
    SECStatus secstatus;

    PK11SlotInfo* slot = NULL;
    CERTCertNicknames *certNickDNS = NULL;
    char **nnptr = NULL;
    int nn = 0;
    apr_array_header_t *names = NULL;
    apr_array_header_t *wild_names = NULL;
    int i, j;

    if (nickname == NULL) {
        return;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
         "Using nickname %s.", nickname);

    *servercert = FindServerCertFromNickname(nickname, clist);

    /* Verify the certificate chain. */
    if (*servercert != NULL) {
        SECCertificateUsage usage = certificateUsageSSLServer;

        if (enforce) {
            if (CERT_VerifyCertificateNow(CERT_GetDefaultCertDB(), *servercert, PR_TRUE, usage, NULL, NULL) != SECSuccess)  {
            nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
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

    /* add ServerAlias entries to hash */
    names = s->names;
    if (names) {
        char **name = (char **)names->elts;
        for (i = 0; i < names->nelts; ++i) {
            ap_str_tolower(name[i]);
            addHashVhostNick(name[i], (char *)nickname);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "SNI ServerAlias: %s -> %s", name[i], nickname);
        }
    }

    /* add ServerAlias entries with wildcards */
    wild_names = s->wild_names;
    if (wild_names) {
        char **wild_name = (char **)wild_names->elts;
        for (j = 0; j < wild_names->nelts; ++j) {
            ap_str_tolower(wild_name[j]);
            addHashVhostNick(wild_name[j], (char *)nickname);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "SNI wildcard: %s -> %s", wild_name[j], nickname);
        }
    }

    /* get valid DNS names from certificate to hash */
    certNickDNS = CERT_GetValidDNSPatternsFromCert(*servercert);

    if (certNickDNS) {
        nnptr = certNickDNS->nicknames;
        nn = certNickDNS->numnicknames;

        while ( nn > 0 ) {
            ap_str_tolower(*nnptr);
            addHashVhostNick(*nnptr, (char *)nickname);
            nnptr++;
            nn--;
        }
        PORT_FreeArena(certNickDNS->arena, PR_FALSE);
    }

    /* Subject/hostname check */
    secstatus = CERT_VerifyCertName(*servercert, s->server_hostname);
    if (secstatus != SECSuccess) {
      char *cert_dns = CERT_GetCommonName(&(*servercert)->subject);
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
		   "Misconfiguration of certificate's CN and virtual name."
		   " The certificate CN has %s. We expected %s as virtual"
		   " name.", cert_dns, s->server_hostname);
      PORT_Free(cert_dns);
    }
    /*
     * Check for certs that are expired or not yet valid and WARN about it.
     * No need to refuse working - the client gets a warning.
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

    secstatus = SSL_ConfigSecureServer(model, *servercert, *serverkey,
                                       *KEAtype);
    if (secstatus != SECSuccess) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "SSL error configuring server: '%s'", nickname);
        nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
        nss_die();
    }

    if (PR_TRUE == sni) {
        if (SSL_SNISocketConfigHook(model, (SSLSNISocketConfig) nssSSLSNISocketConfig, (void*) s) != SECSuccess) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "SSL_SNISocketConfigHook failed");
            nss_log_nss_error(APLOG_MARK, APLOG_ERR, s);
            nss_die();
        }
    }
}


static void nss_init_server_certs(server_rec *s,
                                  apr_pool_t *p,
                                  apr_pool_t *ptemp,
                                  modnss_ctx_t *mctx,
                                  const CERTCertList* clist)
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
            /*
             * Since this is a 'fatal' error, regardless of whether this
             * particular invocation is from a 'server' object or a 'proxy'
             * object, issue all error message(s) as appropriate.
             */
            if ((mctx->sc->enabled == TRUE) &&
                (mctx->sc->server) &&
                (mctx->sc->server->nickname == NULL)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                    "NSSEngine on; no certificate nickname provided by NSSNickname.");
            }

            if ((mctx->sc->proxy_enabled == TRUE) &&
                (mctx->sc->proxy) &&
                (mctx->sc->proxy->nickname == NULL)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                    "NSSProxyEngine on; no certificate nickname provided by NSSProxyNickname.");
            }

            nss_die();
        }

        nss_init_certificate(s, mctx->nickname, &mctx->servercert,
                             &mctx->serverkey, &mctx->serverKEAType,
                             mctx->model, mctx->enforce, mctx->sc->sni,
                             clist);
#ifdef NSS_ENABLE_ECC
        nss_init_certificate(s, mctx->eccnickname, &mctx->eccservercert,
                             &mctx->eccserverkey, &mctx->eccserverKEAType,
                             mctx->model, mctx->enforce, mctx->sc->sni,
                             clist);
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
                                SSLSrvConfigRec *sc,
                                const CERTCertList* clist)
{
    nss_init_ctx(s, p, ptemp, sc->proxy);

    nss_init_server_certs(s, p, ptemp, sc->proxy, clist);
}

static void nss_init_server_ctx(server_rec *s,
                                apr_pool_t *p,
                                apr_pool_t *ptemp,
                                SSLSrvConfigRec *sc,
                                const CERTCertList* clist)
{
    nss_init_server_check(s, p, ptemp, sc->server);

    nss_init_ctx(s, p, ptemp, sc->server);

    nss_init_server_certs(s, p, ptemp, sc->server, clist);
}

/*
 * Configure a particular server
 */
void nss_init_ConfigureServer(server_rec *s,
                              apr_pool_t *p,
                              apr_pool_t *ptemp,
                              SSLSrvConfigRec *sc,
                              const CERTCertList* clist)
{
    if (sc->enabled == TRUE) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "Configuring server for SSL protocol");
        nss_init_server_ctx(s, p, ptemp, sc, clist);
    }

    if (sc->proxy_enabled == TRUE) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "Enabling proxy.");
        nss_init_proxy_ctx(s, p, ptemp, sc, clist);
    }
}

void nss_init_Child(apr_pool_t *p, server_rec *base_server)
{
    SSLModConfigRec *mc = myModConfig(base_server);
    SSLSrvConfigRec *sc;
    server_rec *s;
    int threaded = 0;
    int sslenabled = FALSE;

    mc->pid = getpid(); /* only call getpid() once per-process */

    /*
     *  First, see if ssl is enabled at all
     */
    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);
        /* If any servers have SSL, we want sslenabled set so we
         * can perform further initialization
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
    }

    if (sslenabled == FALSE) { /* we are not an SSL/TLS server */
        return;
    }

    ap_mpm_query(AP_MPMQ_MAX_THREADS, &threaded);
    if (!threaded) {
        if (SSL_InheritMPServerSIDCache(NULL) != SECSuccess) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "SSL_InheritMPServerSIDCache failed");
            nss_log_nss_error(APLOG_MARK, APLOG_ERR, NULL);
        }
    }

    nss_init_SSLLibrary(base_server, mc->pPool);

    /* Configure all virtual servers */
    CERTCertList* clist = PK11_ListCerts(PK11CertListUserUnique, NULL);
    for (s = base_server; s; s = s->next) {
        sc = mySrvConfig(s);
        if (sc->server->servercert == NULL && NSS_IsInitialized()) {
            nss_init_ConfigureServer(s, p, mc->ptemp, sc, clist);
        }
    }
    if (clist) {
        CERT_DestroyCertList(clist);
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
    SSLModConfigRec *mc = myModConfig(base_server);

    if (!NSS_IsInitialized()) {
        return APR_SUCCESS;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, base_server,
        "Shutting down SSL Session ID Cache");

    SSL_ShutdownServerSessionIDCache();

    if (mc->nInitCount == 1)
        nss_init_ChildKill(base_server);

    if (mp) {
        apr_pool_destroy(mp);
        mp = NULL;
    }

    /* NSS_Shutdown() gets called in nss_init_ChildKill */
    return APR_SUCCESS;
}

apr_status_t nss_init_ChildKill(void *data)
{
    SSLSrvConfigRec *sc;
    server_rec *base_server = (server_rec *)data;
    server_rec *s;
    int shutdown = 0;

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

    if (mp) {
        apr_pool_destroy(mp);
        mp = NULL;
    }

    if (shutdown) {
        /* Clear any client-side session cache data */
        SSL_ClearSessionCache();

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
FindServerCertFromNickname(const char* name, const CERTCertList* clist)
{
    CERTCertificate* bestcert = NULL;

    CERTCertListNode *cln;
    PRUint32 bestCertMatchedUsage = 0;
    PRBool bestCertIsValid = PR_FALSE;

    if (name == NULL)
        return NULL;

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

/*
 * Callback made during SSL request to see if SNI was requested and
 * pair it with a configured nickname.
 */
PRInt32 nssSSLSNISocketConfig(PRFileDesc *fd, const SECItem *sniNameArr,
           PRUint32 sniNameArrSize, void *arg)
{
    server_rec *s = (server_rec *)arg;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
		 "nssSSLSNISocketConfig");

    void *pinArg;
    CERTCertificate *cert = NULL;
    SECKEYPrivateKey *privKey = NULL;
    char *nickName = NULL;
    char *vhost = NULL;
    apr_pool_t *str_p;

    PORT_Assert(fd && sniNameArr);
    if (!fd || !sniNameArr) {
        return SSL_SNI_SEND_ALERT;
    }

    apr_pool_create(&str_p, NULL);
    vhost = apr_pstrndup(str_p, (char *) sniNameArr->data, sniNameArr->len);

    /* rfc6125 - Checking of Traditional Domain Names */
    ap_str_tolower(vhost);

    nickName = searchHashVhostbyNick(vhost);
    if (nickName == NULL)  {
        /* search for wildcard_names in serverAlises */
        nickName = searchHashVhostbyNick_match(vhost);
        if (nickName == NULL) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                "SNI: Search for %s failed. Unrecognized name.", vhost);
            goto loser;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,"SNI: Found nickname %s for vhost: %s", nickName, vhost);

    pinArg = SSL_RevealPinArg(fd);

    /* if pinArg is NULL, then we would not get the key and
     * return an error status. */
    cert = PK11_FindCertFromNickname(nickName, &pinArg);
    if (cert == NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
            "Failed to find certificate for nickname: %s", nickName);
        goto loser;
    }
    privKey = PK11_FindKeyByAnyCert(cert, &pinArg);
    if (privKey == NULL) {
        goto loser;
    }

    SSLKEAType certKEA = NSS_FindCertKEAType(cert);

    if (SSL_ConfigSecureServer(fd, cert, privKey, certKEA) != SECSuccess) {
        goto loser; /* Send alert */
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
        "SNI: Successfully paired vhost %s with nickname: %s", vhost, nickName);

    apr_pool_destroy(str_p);
    SECKEY_DestroyPrivateKey(privKey);
    CERT_DestroyCertificate(cert);

    return 0;

loser:
    if (privKey)
        SECKEY_DestroyPrivateKey(privKey);
    if (cert)
        CERT_DestroyCertificate(cert);
    apr_pool_destroy(str_p);

    return SSL_SNI_SEND_ALERT;
}
