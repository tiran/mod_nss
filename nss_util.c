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
#include "ap_mpm.h"
#include "apr_thread_mutex.h"

/*  _________________________________________________________________
**
**  Utility Functions
**  _________________________________________________________________
*/

char *nss_util_vhostid(apr_pool_t *p, server_rec *s)
{
    char *id;
    SSLSrvConfigRec *sc;
    char *host;
    apr_port_t port;

    host = s->server_hostname;
    if (s->port != 0)
        port = s->port;
    else {
        sc = mySrvConfig(s);
        if (sc->enabled == TRUE)
            port = DEFAULT_HTTPS_PORT;
        else
            port = DEFAULT_HTTP_PORT;
    }
    id = apr_psprintf(p, "%s:%lu", host, (unsigned long)port);
    return id;
}

apr_file_t *nss_util_ppopen(server_rec *s, apr_pool_t *p, const char *cmd,
                            const char * const *argv)
{
    apr_procattr_t *procattr;
    apr_proc_t *proc;

    if (apr_procattr_create(&procattr, p) != APR_SUCCESS) 
        return NULL;
    if (apr_procattr_io_set(procattr, APR_FULL_BLOCK, APR_FULL_BLOCK, 
                            APR_FULL_BLOCK) != APR_SUCCESS)
        return NULL;
    if (apr_procattr_dir_set(procattr, 
                             ap_make_dirstr_parent(p, cmd)) != APR_SUCCESS)
        return NULL;
    if (apr_procattr_cmdtype_set(procattr, APR_PROGRAM) != APR_SUCCESS)
        return NULL;
    if ((proc = (apr_proc_t *)apr_pcalloc(p, sizeof(apr_proc_t))) == NULL)
        return NULL;
    if (apr_proc_create(proc, cmd, argv, NULL, procattr, p) != APR_SUCCESS)
        return NULL;
    return proc->out;
}

void nss_util_ppclose(server_rec *s, apr_pool_t *p, apr_file_t *fp)
{
    apr_file_close(fp);
    return;
}

/*
 * Run a filter program and read the first line of its stdout output
 */
char *nss_util_readfilter(server_rec *s, apr_pool_t *p, const char *cmd,
                          const char * const *argv)
{
    static char buf[MAX_STRING_LEN];
    apr_file_t *fp;
    apr_size_t nbytes = 1;
    char c;
    int k;

    if ((fp = nss_util_ppopen(s, p, cmd, argv)) == NULL)
        return NULL;
    /* XXX: we are reading 1 byte at a time here */
    for (k = 0; apr_file_read(fp, &c, &nbytes) == APR_SUCCESS
                && nbytes == 1 && (k < MAX_STRING_LEN-1)     ; ) {
        if (c == '\n' || c == '\r')
            break;
        buf[k++] = c;
    }
    buf[k] = NUL;
    nss_util_ppclose(s, p, fp);

    return buf;
}

static void initializeHashVhostNick() {
    if (NULL != ht)
        return;
    apr_pool_create(&mp, NULL);
    ht = apr_hash_make(mp);
}

char *searchHashVhostbyNick(char *vhost_id) {
    char *searchVal = NULL;

    if (NULL == ht)
        return NULL;

    searchVal = apr_hash_get(ht, vhost_id, APR_HASH_KEY_STRING);

    return searchVal;
}

char *searchHashVhostbyNick_match(char *vhost_id)
{
    char *searchValReg = NULL;
    apr_hash_index_t *hi;

    if (NULL == ht)
        return NULL;

    for (hi = apr_hash_first(NULL, ht); hi; hi = apr_hash_next(hi)) {
        const char *k = NULL;
        const char *v = NULL;
        
        apr_hash_this(hi, (const void**)&k, NULL, (void**)&v);
        if (!ap_strcasecmp_match(vhost_id, k)) {
            searchValReg = apr_hash_get(ht, k, APR_HASH_KEY_STRING);
            return searchValReg; 
        }
    }
    return NULL;
}

void addHashVhostNick(char *vhost_id, char *nickname) {
    if (ht == NULL) {
        initializeHashVhostNick();
    }
    
    if (searchHashVhostbyNick(vhost_id) == NULL) {
        apr_hash_set(ht, apr_pstrdup(mp, vhost_id), APR_HASH_KEY_STRING, 
                     apr_pstrdup(mp, nickname));
    }
}
