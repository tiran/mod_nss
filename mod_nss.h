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

#ifndef __MOD_SSL_H__
#define __MOD_SSL_H__

/* Apache headers */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_connection.h"
#include "http_request.h"
#include "http_protocol.h"
#include "util_script.h"
#include "util_filter.h"
#include "mpm.h"
#include "apr.h"
#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_tables.h"
#include "apr_lib.h"
#include "apr_fnmatch.h"
#include "apr_strings.h"
#include "apr_dbm.h"
#include "apr_rmm.h"
#include "apr_shm.h"
#include "apr_global_mutex.h"
#include "apr_optional.h"

#define MOD_NSS_VERSION AP_SERVER_BASEREVISION

/* NSPR headers */
#include "nspr.h"
#include <prerror.h>
#include <prnetdb.h>

/* NSS header files */

#include <pk11func.h>
#include <ssl.h>
#include <nss.h>
#include <sslproto.h>

/* The #ifdef macros are only defined AFTER including the above
 * therefore we cannot include these system files at the top  :-(
 */
#if APR_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h> /* needed for STDIN_FILENO et.al., at least on FreeBSD */
#endif

/* mod_ssl headers */
#include "nss_expr.h"

/*
 * Provide reasonable default for some defines
 */
#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif
#ifndef PFALSE
#define PFALSE ((void *)FALSE)
#endif
#ifndef PTRUE
#define PTRUE ((void *)TRUE)
#endif
#ifndef UNSET
#define UNSET (-1)
#endif
#ifndef NUL
#define NUL '\0'
#endif

/*
 * Provide reasonable defines for some types
 */
#ifndef BOOL
#define BOOL unsigned int
#endif
#ifndef UCHAR
#define UCHAR unsigned char
#endif

/*
 * Provide useful shorthands
 */
#define strEQ(s1,s2)     (strcmp(s1,s2)        == 0)
#define strNE(s1,s2)     (strcmp(s1,s2)        != 0)
#define strEQn(s1,s2,n)  (strncmp(s1,s2,n)     == 0)
#define strNEn(s1,s2,n)  (strncmp(s1,s2,n)     != 0)

#define strcEQ(s1,s2)    (strcasecmp(s1,s2)    == 0)
#define strcNE(s1,s2)    (strcasecmp(s1,s2)    != 0)
#define strcEQn(s1,s2,n) (strncasecmp(s1,s2,n) == 0)
#define strcNEn(s1,s2,n) (strncasecmp(s1,s2,n) != 0)

#define strIsEmpty(s)    (s == NULL || s[0] == NUL)

#define myConnConfig(c) \
(SSLConnRec *)ap_get_module_config(c->conn_config, &nss_module)
#define myCtxConfig(sslconn, sc) (sslconn->is_proxy ? sc->proxy : sc->server)
#define myConnConfigSet(c, val) \
ap_set_module_config(c->conn_config, &nss_module, val)
#define mySrvConfig(srv) (SSLSrvConfigRec *)ap_get_module_config(srv->module_config,  &nss_module)
#define myDirConfig(req) (SSLDirConfigRec *)ap_get_module_config(req->per_dir_config, &nss_module)
#define myModConfig(srv) (mySrvConfig((srv)))->mc

/*
 * Defaults for the configuration
 */
#ifndef SSL_SESSION_CACHE_TIMEOUT
#define SSL_SESSION_CACHE_TIMEOUT  100
#endif

#ifndef SSL3_SESSION_CACHE_TIMEOUT 
#define SSL3_SESSION_CACHE_TIMEOUT  86400
#endif

#ifndef SSL_SESSION_CACHE_SIZE
#define SSL_SESSION_CACHE_SIZE     10000
#endif

/*
 * Define the SSL options
 */
#define SSL_OPT_NONE           (0)
#define SSL_OPT_RELSET         (1<<0)
#define SSL_OPT_STDENVVARS     (1<<1)
#define SSL_OPT_COMPATENVVARS  (1<<2)
#define SSL_OPT_EXPORTCERTDATA (1<<3)
#define SSL_OPT_FAKEBASICAUTH  (1<<4)
#define SSL_OPT_STRICTREQUIRE  (1<<5)
#define SSL_OPT_OPTRENEGOTIATE (1<<6)
#define SSL_OPT_ALL            (SSL_OPT_STDENVVARS|SSL_OPT_COMPATENVVAR|SSL_OPT_EXPORTCERTDATA|SSL_OPT_FAKEBASICAUTH|SSL_OPT_STRICTREQUIRE|SSL_OPT_OPTRENEGOTIATE)
typedef int ssl_opt_t;

/*
 * Define the SSL requirement structure
 */ 
typedef struct {
    char     *cpExpr;
    ssl_expr *mpExpr;
} ssl_require_t;

/*
 * Define the SSL verify levels
 */
typedef enum {
    SSL_CVERIFY_UNSET           = UNSET,
    SSL_CVERIFY_NONE            = 0,
    SSL_CVERIFY_OPTIONAL        = 1,
    SSL_CVERIFY_REQUIRE         = 2,
    SSL_CVERIFY_OPTIONAL_NO_CA  = 3
} ssl_verify_t;

/*
 * Define the SSL pass phrase dialog types
 */
typedef enum {
    SSL_PPTYPE_UNSET   = UNSET,
    SSL_PPTYPE_BUILTIN = 0,
    SSL_PPTYPE_FILE    = 1,
} ssl_pphrase_t;

/*
 * Define the mod_ssl per-module configuration structure
 * (i.e. the global configuration for each httpd process)
 */

typedef struct {
    PRFileDesc *ssl;
    const char *client_dn;
    CERTCertificate *client_cert; 
    int is_proxy;
    int disabled;
    int non_ssl_request;
    apr_socket_t * client_socket;
} SSLConnRec;

typedef struct {
    pid_t           pid;
    int             nInitCount;
    apr_pool_t     *pPool;
    const char     *pCertificateDatabase;

    /* config for SSL session cache */
    int             session_cache_size;
    int             session_cache_timeout;
    int             ssl3_session_cache_timeout;

    /* config for handling encrypted keys */
    ssl_pphrase_t   pphrase_dialog_type;
    const char     *pphrase_dialog_path;
    const char     *pphrase_dialog_helper;

    apr_proc_t      proc;
    apr_procattr_t *procattr;

    struct {
        void *pV1, *pV2, *pV3, *pV4, *pV5, *pV6, *pV7, *pV8, *pV9, *pV10;
    } rCtx;
} SSLModConfigRec;

typedef struct SSLSrvConfigRec SSLSrvConfigRec;

/* stuff related to authentication that can also be per-dir */
typedef struct {
    const char  *cipher_suite;
    const char  *protocols;

    /* for client or downstream server authentication */
    ssl_verify_t verify_mode;
} modnss_auth_ctx_t;

typedef struct {
    SSLSrvConfigRec *sc; /* pointer back to server config */
    
    char *cipherSuite;

    int ssl2;
    int ssl3;
    int tls;
    int tlsrollback;
    int enforce;
    const char *nickname;

    CERTCertificate   *servercert;
    SECKEYPrivateKey  *serverkey;
    SSLKEAType         serverKEAType;

    PRFileDesc        *model;              /* used to model an SSL socket */

    modnss_auth_ctx_t auth;
} modnss_ctx_t;

struct SSLSrvConfigRec {
    SSLModConfigRec *mc;
    BOOL             enabled;
    BOOL             proxy_enabled;
    const char      *vhost_id;
    int              vhost_id_len;
    modnss_ctx_t    *server;
    modnss_ctx_t    *proxy;
};

/*
 * Define the mod_ssl per-directory configuration structure
 * (i.e. the local configuration for all <Directory>
 *  and .htaccess contexts)
 */
typedef struct {
    BOOL                bSSLRequired;
    apr_array_header_t *aRequirement;
    int                 nOptions;
    int                 nOptionsAdd;
    int                 nOptionsDel;
    const char         *szCipherSuite;
    ssl_verify_t   nVerifyClient;
    const char         *szCACertificatePath;
    const char         *szCACertificateFile;
    const char         *szUserName;
} SSLDirConfigRec;

/*
 * Cipher definitions
 */
typedef struct
{
    const char *name;
    int num;
    int fortezza_only;
    PRInt32 version; // protocol version valid for this cipher
} cipher_properties;
 
enum sslversion { SSL2=1, SSL3=2, TLS=4};

/* the table itself is defined in ssl_engine_init.c */
#define ciphernum 23

/*
 *  function prototypes
 */

/*  API glue structures  */
extern module AP_MODULE_DECLARE_DATA nss_module;

/*  configuration handling   */
SSLModConfigRec *ssl_config_global_create(server_rec *);
void *ssl_config_perdir_create(apr_pool_t *p, char *dir);
void *ssl_config_perdir_merge(apr_pool_t *p, void *basev, void *addv);
void *ssl_config_server_create(apr_pool_t *p, server_rec *s);
void *ssl_config_server_merge(apr_pool_t *p, void *basev, void *addv);
const char *ssl_cmd_SSLEngine(cmd_parms *, void *, int);
const char *ssl_cmd_SSLCertificateDatabase(cmd_parms *cmd, void *dcfg, const char *arg);
const char *ssl_cmd_SSLCipherSuite(cmd_parms *cmd, void *dcfg, const char *arg);
const char *ssl_cmd_SSLVerifyClient(cmd_parms *cmd, void *dcfg, const char *arg);
const char *ssl_cmd_SSLProtocol(cmd_parms *cmd, void *dcfg, const char *arg);
const char *ssl_cmd_SSLNickname(cmd_parms *cmd, void *dcfg, const char *arg);
const char *ssl_cmd_SSLEnforceValidCerts(cmd_parms *, void *, int);
const char *ssl_cmd_SSLSessionCacheTimeout(cmd_parms *cmd, void *dcfg, const char *arg);
const char *ssl_cmd_SSL3SessionCacheTimeout(cmd_parms *cmd, void *dcfg, const char *arg);
const char *ssl_cmd_SSLSessionCacheSize(cmd_parms *cmd, void *dcfg, const char *arg);
const char *ssl_cmd_SSLPassPhraseDialog(cmd_parms *cmd, void *dcfg, const char *arg);
const char *ssl_cmd_SSLPassPhraseHelper(cmd_parms *cmd, void *dcfg, const char *arg);
const char *ssl_cmd_SSLUserName(cmd_parms *cmd, void *dcfg, const char *arg);
const char *ssl_cmd_SSLOptions(cmd_parms *, void *, const char *);
const char *ssl_cmd_SSLRequireSSL(cmd_parms *cmd, void *dcfg);
const char  *ssl_cmd_SSLRequire(cmd_parms *, void *, const char *);

/*  module initialization  */
int  ssl_init_Module(apr_pool_t *, apr_pool_t *, apr_pool_t *, server_rec *);
void ssl_init_Child(apr_pool_t *, server_rec *);
void ssl_init_ConfigureServer(server_rec *, apr_pool_t *, apr_pool_t *, SSLSrvConfigRec *);
apr_status_t ssl_init_ModuleKill(void *data);
int ssl_parse_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum]);

/* Apache API hooks */
int ssl_hook_Translate(request_rec *r);
int ssl_hook_UserCheck(request_rec *r);
int ssl_hook_Fixup(request_rec *r);
int ssl_hook_Access(request_rec *r);
int ssl_hook_Auth(request_rec *r);
int ssl_hook_ReadReq(request_rec *r);

/*  Variables  */
void         ssl_var_register(void);
char        *ssl_var_lookup(apr_pool_t *, server_rec *, conn_rec *, request_rec *, char *);
void         ssl_var_log_config_register(apr_pool_t *p);

APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup,
                        (apr_pool_t *, server_rec *,
                         conn_rec *, request_rec *, 
                         char *));

/* An optional function which returns non-zero if the given connection
 * is using SSL/TLS. */
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

/* Proxy Support */
int ssl_engine_disable(conn_rec *c);

APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec *));

/* I/O */
PRFileDesc * ssl_io_new_fd();
int ssl_io_layer_init();
void ssl_io_filter_init(conn_rec *c, PRFileDesc *ssl);
void ssl_io_filter_register(apr_pool_t *p);

/*  Utility Functions  */
char        *ssl_util_vhostid(apr_pool_t *, server_rec *);
void         ssl_util_strupper(char *);
void         ssl_util_uuencode(char *, const char *, BOOL);
void         ssl_util_uuencode_binary(unsigned char *, const unsigned char *, int, BOOL);
apr_file_t  *ssl_util_ppopen(server_rec *, apr_pool_t *, const char *,
                             const char * const *);
void         ssl_util_ppclose(server_rec *, apr_pool_t *, apr_file_t *);
char        *ssl_util_readfilter(server_rec *, apr_pool_t *, const char *,
                                 const char * const *);

/* Pass Phrase Handling */
SECStatus ssl_Init_Tokens(server_rec *s);

/* Logging */
void ssl_log_ssl_error(const char *file, int line, int level, server_rec *s);
void ssl_die(void);

/* NSS callback */
SECStatus ssl_AuthCertificate(void *arg, PRFileDesc *socket, PRBool checksig, PRBool isServer);
#endif /* __MOD_SSL_H__ */
