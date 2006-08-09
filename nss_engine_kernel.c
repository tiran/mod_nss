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
#include "secerr.h"

static void HandshakeDone(PRFileDesc *fd, void *doneflag);

/*
 *  Post Read Request Handler
 */
int nss_hook_ReadReq(request_rec *r)
{
    SSLConnRec *sslconn = myConnConfig(r->connection);
    PRFileDesc *ssl = sslconn ? sslconn->ssl : NULL;

    if (!sslconn) {
        return DECLINED;
    }

    if (sslconn->non_nss_request) {
        const char *errmsg;
        char *thisurl;
        char *thisport = "";
        int port = ap_get_server_port(r);

        if (!ap_is_default_port(port, r)) {
            thisport = apr_psprintf(r->pool, ":%u", port);
        }

        thisurl = ap_escape_html(r->pool,
                                 apr_psprintf(r->pool, "https://%s%s/",
                                              ap_get_server_name(r),
                                              thisport));

        errmsg = apr_psprintf(r->pool,
                              "Reason: You're speaking plain HTTP "
                              "to an SSL-enabled server port.<br />\n"
                              "Instead use the HTTPS scheme to access "
                              "this URL, please.<br />\n"
                              "<blockquote>Hint: "
                              "<a href=\"%s\"><b>%s</b></a></blockquote>",
                              thisurl, thisurl);

        apr_table_setn(r->notes, "error-notes", errmsg);
        /* Now that we have caught this error, forget it. we are done
         * with using SSL on this request.
         */
        sslconn->non_nss_request = 0;


        return HTTP_BAD_REQUEST;
    }

    /* Get the SSL connection structure and perform the
     * delayed interlinking from SSL back to request_rec
     */
    if (!ssl) {
        return DECLINED; 
    }

    /*
     * Log information about incoming HTTPS requests
     */
    if (r->server->loglevel >= APLOG_INFO && ap_is_initial_req(r)) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                     "%s HTTPS request received for child %ld (server %s)",
                     (r->connection->keepalives <= 0 ?
                     "Initial (No.1)" :
                     apr_psprintf(r->pool, "Subsequent (No.%d)",
                                  r->connection->keepalives+1)),
                     r->connection->id,
                     nss_util_vhostid(r->pool, r->server));
    }

    return DECLINED;
}

/*
 *  Access Handler
 */
int nss_hook_Access(request_rec *r)
{
    SSLDirConfigRec *dc = myDirConfig(r);
    SSLSrvConfigRec *sc = mySrvConfig(r->server);
    SSLConnRec *sslconn = myConnConfig(r->connection);
    PRFileDesc *ssl     = sslconn ? sslconn->ssl : NULL;
    apr_array_header_t *requires; 
    nss_require_t *nss_requires; 
    char *cp;
    int ok, i;
    BOOL renegotiate = FALSE, renegotiate_quick = FALSE;
    CERTCertificate *cert;
    CERTCertificate *peercert;
    int verify_old, verify;
    extern cipher_properties ciphers_def[];
    PRBool ciphers_old[ciphernum];
    PRBool ciphers_new[ciphernum];
    char * cipher = NULL;
    char * ciphers = NULL;
    PRBool cipher_in_list = PR_FALSE;

    /*
     * Support for SSLRequireSSL directive
     */
    if (dc->bSSLRequired && !ssl) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "access to %s failed, reason: %s",
                      r->filename, "SSL connection required");

        /* remember forbidden access for strict require option */
        apr_table_setn(r->notes, "ssl-access-forbidden", "1");

        return HTTP_FORBIDDEN;
    }

    /*
     * Check to see if SSL protocol is on
     */
    if (!(sc->enabled || ssl)) {
        return DECLINED;
    }
    /*
     * Support for per-directory reconfigured SSL connection parameters.
     * 
     * This is implemented by forcing an SSL renegotiation with the
     * reconfigured parameter suite. But Apache's internal API processing
     * makes our life very hard here, because when internal sub-requests occur
     * we nevertheless should avoid multiple unnecessary SSL handshakes (they
     * require extra network I/O and especially time to perform).
     *
     * But the optimization for filtering out the unnecessary handshakes isn't
     * obvious and trivial.  Especially because while Apache is in its
     * sub-request processing the client could force additional handshakes,
     * too. And these take place perhaps without our notice. So the only
     * possibility is to explicitly _ask_ OpenSSL whether the renegotiation
     * has to be performed or not. It has to performed when some parameters
     * which were previously known (by us) are not those we've now
     * reconfigured (as known by OpenSSL) or (in optimized way) at least when
     * the reconfigured parameter suite is stronger (more restrictions) than
     * the currently active one.
     */
    
    /*
     * Override of NSSCipherSuite
     *
     * We provide two options here:
     *
     * o The paranoid and default approach where we force a renegotiation when
     *   the cipher suite changed in _any_ way (which is straight-forward but
     *   often forces renegotiations too often and is perhaps not what the
     *   user actually wanted).
     *
     * o The optimized and still secure way where we force a renegotiation
     *   only if the currently active cipher is no longer contained in the
     *   reconfigured/new cipher suite. Any other changes are not important
     *   because it's the servers choice to select a cipher from the ones the
     *   client supports. So as long as the current cipher is still in the new
     *   cipher suite we're happy. Because we can assume we would have
     *   selected it again even when other (better) ciphers exists now in the
     *   new cipher suite. This approach is fine because the user explicitly
     *   has to enable this via ``NSSOptions +OptRenegotiate''. So we do no
     *   implicit optimizations.
     */
    if (dc->szCipherSuite) {
        /* remember old state */
        for (i=0; i < ciphernum; i++) {
            SSL_CipherPrefGet(ssl, ciphers_def[i].num, &ciphers_old[i]);
        }

        if (dc->nOptions & SSL_OPT_OPTRENEGOTIATE) {
            int on, keySize, secretKeySize;
            char *issuer, *subject;

            SSL_SecurityStatus(ssl, &on, &cipher,
                               &keySize, &secretKeySize, &issuer,
                               &subject);
        }

        /* configure new state */

        ciphers = strdup(dc->szCipherSuite);
        if (nss_parse_ciphers(r->server, ciphers, ciphers_new) < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                         r->server,
                         "Unable to reconfigure (per-directory) "
                         "permitted SSL ciphers");
            nss_log_nss_error(APLOG_MARK, APLOG_ERR, r->server);
            free(ciphers);
    
            return HTTP_FORBIDDEN;
        }
        free(ciphers);

        /* Actually enable the selected ciphers. Also check to
           see if the existing cipher is in the new list for
           a possible optimization later. */

        for (i=0; i<ciphernum;i++) {
            if (cipher && !strcasecmp(cipher, ciphers_def[i].name)) {
                if (ciphers_new[i] == PR_TRUE)
                    cipher_in_list = PR_TRUE;
            }
            SSL_CipherPrefSet(ssl, ciphers_def[i].num, ciphers_new[i]);
        }

        /* determine whether a renegotiation has to be forced */

        if (dc->nOptions & SSL_OPT_OPTRENEGOTIATE) {
            if (cipher_in_list != PR_TRUE)
                renegotiate = TRUE;
        }
        else {
            /* paranoid way */
            for (i=0; i<ciphernum;i++) {
                if (ciphers_new[i] != ciphers_old[i]) {
                    renegotiate = TRUE;
                    break;
                }
            }
        }

        /* tracing */
        if (renegotiate) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Reconfigured cipher suite will force renegotiation");
        }
    }

    /*
     * override of SSLVerifyClient
     *
     * We force a renegotiation if the reconfigured/new verify type is
     * stronger than the currently active verify type.
     *
     * The order is: none << optional_no_ca << optional << require
     *
     * Additionally the following optimization is possible here: When the
     * currently active verify type is "none" but a client certificate is
     * already known/present, it's enough to manually force a client
     * verification but at least skip the I/O-intensive renegotation
     * handshake.
     */
    if (dc->nVerifyClient != SSL_CVERIFY_UNSET) {
        PRInt32 on;

        /* remember old state */
        SSL_OptionGet(ssl, SSL_REQUIRE_CERTIFICATE, &on);
        if (on == PR_TRUE) {
            verify_old = SSL_CVERIFY_REQUIRE;
        } else {
            SSL_OptionGet(ssl, SSL_REQUEST_CERTIFICATE, &on);
            if (on == PR_TRUE)
                verify_old = SSL_CVERIFY_OPTIONAL;
            else
                verify_old = SSL_CVERIFY_NONE;
        }

        /* configure new state */
        verify = dc->nVerifyClient;

        if (verify == SSL_CVERIFY_REQUIRE) {
            SSL_OptionSet(ssl, SSL_REQUEST_CERTIFICATE, PR_TRUE);
            SSL_OptionSet(ssl, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NO_ERROR);
        } else if (verify == SSL_CVERIFY_OPTIONAL) {
            SSL_OptionSet(ssl, SSL_REQUEST_CERTIFICATE, PR_TRUE);
            SSL_OptionSet(ssl, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NEVER);
        } else {
            SSL_OptionSet(ssl, SSL_REQUEST_CERTIFICATE, PR_FALSE);
            SSL_OptionSet(ssl, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NEVER);
        }
    
        /* determine whether we've to force a renegotiation */
        if (!renegotiate && verify != verify_old) {
            if (((verify_old == SSL_CVERIFY_NONE) &&
                 (verify     != SSL_CVERIFY_NONE)) ||

                (!(verify_old & SSL_CVERIFY_OPTIONAL) &&
                  (verify     & SSL_CVERIFY_OPTIONAL)) ||

                (!(verify_old & SSL_CVERIFY_REQUIRE) &&
                  (verify     & SSL_CVERIFY_REQUIRE)))
            {
                renegotiate = TRUE;
                /* optimization */

                if ((dc->nOptions & SSL_OPT_OPTRENEGOTIATE) &&
                    (verify_old == SSL_CVERIFY_NONE) &&
                    ((peercert = SSL_PeerCertificate(ssl)) != NULL))
                {
                    renegotiate_quick = TRUE;
                    CERT_DestroyCertificate(peercert);
                }

                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                             r->server,
                             "Changed client verification type will force "
                             "%srenegotiation",
                             renegotiate_quick ? "quick " : "");
            }
        }
    }

    /* If a renegotiation is now required for this location, and the
     * request includes a message body (and the client has not
     * requested a "100 Continue" response), then the client will be
     * streaming the request body over the wire already.  In that
     * case, it is not possible to stop and perform a new SSL
     * handshake immediately; once the SSL library moves to the
     * "accept" state, it will reject the SSL packets which the client
     * is sending for the request body.
     * 
     * To allow authentication to complete in this auth hook, the
     * solution used here is to fill a (bounded) buffer with the
     * request body, and then to reinject that request body later.
     */
    if (renegotiate && !renegotiate_quick
        && (apr_table_get(r->headers_in, "transfer-encoding")
            || (apr_table_get(r->headers_in, "content-length")
                && strcmp(apr_table_get(r->headers_in, "content-length"), "0")))
        && !r->expecting_100) {
        int rv;

        /* Fill the I/O buffer with the request body if possible. */
        rv = nss_io_buffer_fill(r);

        if (rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "could not buffer message body to allow "
                          "SSL renegotiation to proceed");
            return rv;
        }
    }

    /*
     * now do the renegotiation if anything was actually reconfigured
     */
    if (renegotiate) {
        /*
         * Now we force the SSL renegotation by sending the Hello Request
         * message to the client. Here we have to do a workaround: Actually
         * OpenSSL returns immediately after sending the Hello Request (the
         * intent AFAIK is because the SSL/TLS protocol says it's not a must
         * that the client replies to a Hello Request). But because we insist
         * on a reply (anything else is an error for us) we have to go to the
         * ACCEPT state manually. Using SSL_set_accept_state() doesn't work
         * here because it resets too much of the connection.  So we set the
         * state explicitly and continue the handshake manually.
         */
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                     "Requesting connection re-negotiation");

        if (renegotiate_quick) {
            SECStatus rv;
            CERTCertificate *peerCert;
            void *pinArg;

            /* perform just a manual re-verification of the peer */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Performing quick renegotiation: "
                         "just re-verifying the peer");

            peerCert = SSL_PeerCertificate(sslconn->ssl);
 
            pinArg = SSL_RevealPinArg(sslconn->ssl);
 
            rv = CERT_VerifyCertNow(CERT_GetDefaultCertDB(),
                                    peerCert,
                                    PR_TRUE,
                                    certUsageSSLClient,
                                    pinArg);
 
            CERT_DestroyCertificate(peerCert); 

            if (rv != SECSuccess) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "Re-negotiation handshake failed: "
                             "Client verification failed");

                return HTTP_FORBIDDEN;
            }

            /* The cert is ok, fall through to the check SSLRequires */
        }
        else {
            int handshake_done = 0;
            int result = 0;

            /* do a full renegotiation */
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Performing full renegotiation: "
                         "complete handshake protocol");

            /* Do NOT call SSL_ResetHandshake as this will tear down the
             * existing connection.
             */
            if (SSL_HandshakeCallback(ssl, HandshakeDone, (void *)&handshake_done) || SSL_ReHandshake(ssl, PR_TRUE)) {
                int errCode = PR_GetError();
                if (errCode == SEC_ERROR_INVALID_ARGS) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Re-negotation request failed: "
                         "trying to do client authentication on a non-SSL3 connection");
                } else {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Re-negotation request failed: "
                         "returned error %d", errCode);
                }
                r->connection->aborted = 1;
                return HTTP_FORBIDDEN;
            }

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                         "Awaiting re-negotiation handshake");

            while (!handshake_done) {
                apr_bucket_brigade *bb;
                conn_rec *c = r->connection;

                bb = apr_brigade_create(c->pool, c->bucket_alloc);
                result = SSL_ForceHandshake(ssl);
                if (result >= 0) {

                    /* This flag gets set by the NSS callback */
                    if (handshake_done)
                        break;

                    /* We need to force a read so the SSL data can be
                     * handled
                     */
                    if ((result = ap_get_brigade(c->input_filters, bb,
                       AP_MODE_GETLINE, APR_BLOCK_READ, HUGE_STRING_LEN) !=
                       APR_SUCCESS || APR_BRIGADE_EMPTY(bb))) {
                         apr_brigade_destroy(bb);
                         break;
                    }
                } else {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "Read error %d", PR_GetError());
                    break;
                }
            }

            /* Reset the ssl callback */
            SSL_HandshakeCallback(ssl, NULL, NULL);

            if (result < 0) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                             "Re-negotiation handshake failed: "
                        "Not accepted by client!?");

#if 0
                r->connection->aborted = 1;
#endif
                return HTTP_FORBIDDEN;
            }
        }

        /*
         * Remember the peer certificate's DN
         */
        if ((cert = SSL_PeerCertificate(ssl))) {
            if (sslconn->client_cert) {
                CERT_DestroyCertificate(sslconn->client_cert);
            }
            sslconn->client_cert = cert;
            sslconn->client_dn = NULL;
        }
    }

    /* If we're trying to have the user name set from a client
     * certificate then we need to set it here. This should be safe as
     * the user name probably isn't important from an auth checking point
     * of view as the certificate supplied acts in that capacity.
     * However, if FakeAuth is being used then this isn't the case so
     * we need to postpone setting the username until later.
     */
    if ((dc->nOptions & SSL_OPT_FAKEBASICAUTH) == 0 && dc->szUserName) {
        char *val = nss_var_lookup(r->pool, r->server, r->connection,
                                   r, (char *)dc->szUserName);
        if (val && val[0])
            r->user = val;
    }

    /*
     * Check SSLRequire boolean expressions
     */
    requires = dc->aRequirement;
    nss_requires = (nss_require_t *)requires->elts;

    for (i = 0; i < requires->nelts; i++) {
        nss_require_t *req = &nss_requires[i];
        ok = nss_expr_exec(r, req->mpExpr);

        if (ok < 0) {
            cp = apr_psprintf(r->pool,
                              "Failed to execute "
                              "SSL requirement expression: %s",
                              nss_expr_get_error());

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "access to %s failed, reason: %s",
                          r->filename, cp);

            /* remember forbidden access for strict require option */
            apr_table_setn(r->notes, "ssl-access-forbidden", "1");

            return HTTP_FORBIDDEN;
        }

        if (ok != 1) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "Access to %s denied for %s "
                         "(requirement expression not fulfilled)",
                         r->filename, r->connection->remote_ip);

            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                         "Failed expression: %s", req->cpExpr);

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "access to %s failed, reason: %s",
                          r->filename,
                          "SSL requirement expression not fulfilled "
                          "(see SSL logfile for more details)");

            /* remember forbidden access for strict require option */
            apr_table_setn(r->notes, "ssl-access-forbidden", "1");

            return HTTP_FORBIDDEN;
        }
    }

    /*
     * Else access is granted from our point of view (except vendor
     * handlers override). But we have to return DECLINED here instead
     * of OK, because mod_auth and other modules still might want to
     * deny access.
     */

    return DECLINED;
}

/*
 *  Authentication Handler:
 *  Fake a Basic authentication from the X509 client certificate.
 *
 *  This must be run fairly early on to prevent a real authentication from
 *  occuring, in particular it must be run before anything else that
 *  authenticates a user.  This means that the Module statement for this
 *  module should be LAST in the Configuration file.
 */
int nss_hook_UserCheck(request_rec *r)
{
    SSLConnRec *sslconn = myConnConfig(r->connection);
    SSLSrvConfigRec *sc = mySrvConfig(r->server);
    SSLDirConfigRec *dc = myDirConfig(r);
    char *clientdn;
    const char *auth_line, *username, *password;
     
    /*
     * Additionally forbid access (again)
     * when strict require option is used.
     */
    if ((dc->nOptions & SSL_OPT_STRICTREQUIRE) &&
        (apr_table_get(r->notes, "ssl-access-forbidden")))
    {
        return HTTP_FORBIDDEN;
    }

    /*
     * We decline when we are in a subrequest.  The Authorization header
     * would already be present if it was added in the main request.
     */
    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    /*
     * Make sure the user is not able to fake the client certificate
     * based authentication by just entering an X.509 Subject DN
     * ("/XX=YYY/XX=YYY/..") as the username and "password" as the
     * password.
     */
    if ((auth_line = apr_table_get(r->headers_in, "Authorization"))) {
        if (strcEQ(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
            while ((*auth_line == ' ') || (*auth_line == '\t')) {
                auth_line++;
            }

            auth_line = ap_pbase64decode(r->pool, auth_line);
            username = ap_getword_nulls(r->pool, &auth_line, ':');
            password = auth_line;

            if ((username[0] == '/') && strEQ(password, "password")) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "Encountered FakeBasicAuth spoof: %s", username);
                return HTTP_FORBIDDEN;
            }
        }
    }

    /* 
     * We decline operation in various situations...
     * - NSSOptions +FakeBasicAuth not configured
     * - r->user already authenticated
     * - ssl not enabled
     * - client did not present a certificate
     */
    if (!(sc->enabled && sslconn && sslconn->ssl && sslconn->client_cert) ||
        !(dc->nOptions & SSL_OPT_FAKEBASICAUTH) || r->user)
    {
        return DECLINED;
    }

    if (!sslconn->client_dn) {
        char * cp = CERT_GetCommonName(&sslconn->client_cert->subject);
        sslconn->client_dn = apr_pstrdup(r->connection->pool, cp);
        PORT_Free(cp);
    }

    clientdn = (char *)sslconn->client_dn;

    /*
     * Fake a password - which one would be immaterial, as, it seems, an empty
     * password in the users file would match ALL incoming passwords, if only
     * we were using the standard crypt library routine. Unfortunately, OpenSSL
     * "fixes" a "bug" in crypt and thus prevents blank passwords from
     * working.  (IMHO what they really fix is a bug in the users of the code
     * - failing to program correctly for shadow passwords).  We need,
     * therefore, to provide a password. This password can be matched by
     * adding the string "xxj31ZMTZzkVA" as the password in the user file.
     * This is just the crypted variant of the word "password" ;-)
     *
     * The NSS module is retaining this for compatibility purposes.
     */
    auth_line = apr_pstrcat(r->pool, "Basic ",
                            ap_pbase64encode(r->pool,
                                             apr_pstrcat(r->pool, clientdn,
                                                         ":password", NULL)),
                            NULL);
    apr_table_set(r->headers_in, "Authorization", auth_line);
    
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                 "Faking HTTP Basic Auth header: \"Authorization: %s\"",
                 auth_line);

    return DECLINED;
}

/* authorization phase */
int nss_hook_Auth(request_rec *r)
{
    SSLDirConfigRec *dc = myDirConfig(r);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "nss_hook_Auth");
    /*
     * Additionally forbid access (again) 
     * when strict require option is used.
     */
    if ((dc->nOptions & SSL_OPT_STRICTREQUIRE) &&
        (apr_table_get(r->notes, "ssl-access-forbidden")))
    {
        return HTTP_FORBIDDEN;
    }

    return DECLINED;
}

/*  
 *   Fixup Handler
 */ 
    
static const char *nss_hook_Fixup_vars[] = {
    "SSL_VERSION_INTERFACE",
    "SSL_VERSION_LIBRARY",
    "SSL_PROTOCOL",
    "SSL_CIPHER",
    "SSL_CIPHER_NAME",
    "SSL_CIPHER_EXPORT",
    "SSL_CIPHER_USEKEYSIZE",
    "SSL_CIPHER_ALGKEYSIZE",
    "SSL_CLIENT_VERIFY",
    "SSL_CLIENT_M_VERSION",
    "SSL_CLIENT_M_SERIAL",
    "SSL_CLIENT_V_START",
    "SSL_CLIENT_V_END",
    "SSL_CLIENT_V_REMAIN",
    "SSL_CLIENT_S_DN",
    "SSL_CLIENT_S_DN_C",
    "SSL_CLIENT_S_DN_ST",
    "SSL_CLIENT_S_DN_L",
    "SSL_CLIENT_S_DN_O",
    "SSL_CLIENT_S_DN_OU",
    "SSL_CLIENT_S_DN_CN",
    "SSL_CLIENT_S_DN_T",
    "SSL_CLIENT_S_DN_I",
    "SSL_CLIENT_S_DN_G",
    "SSL_CLIENT_S_DN_S",
    "SSL_CLIENT_S_DN_D",
    "SSL_CLIENT_S_DN_UID",
    "SSL_CLIENT_S_DN_Email",
    "SSL_CLIENT_I_DN",
    "SSL_CLIENT_I_DN_C",
    "SSL_CLIENT_I_DN_ST",
    "SSL_CLIENT_I_DN_L",
    "SSL_CLIENT_I_DN_O",
    "SSL_CLIENT_I_DN_OU",
    "SSL_CLIENT_I_DN_CN",
    "SSL_CLIENT_I_DN_T",
    "SSL_CLIENT_I_DN_I",
    "SSL_CLIENT_I_DN_G",
    "SSL_CLIENT_I_DN_S",
    "SSL_CLIENT_I_DN_D",
    "SSL_CLIENT_I_DN_UID",
    "SSL_CLIENT_I_DN_Email",
    "SSL_CLIENT_A_KEY",
    "SSL_CLIENT_A_SIG",
    "SSL_SERVER_M_VERSION",
    "SSL_SERVER_M_SERIAL",
    "SSL_SERVER_V_START",
    "SSL_SERVER_V_END",
    "SSL_SERVER_S_DN",
    "SSL_SERVER_S_DN_C",
    "SSL_SERVER_S_DN_ST",
    "SSL_SERVER_S_DN_L",
    "SSL_SERVER_S_DN_O",
    "SSL_SERVER_S_DN_OU",
    "SSL_SERVER_S_DN_CN",
    "SSL_SERVER_S_DN_T",
    "SSL_SERVER_S_DN_I",
    "SSL_SERVER_S_DN_G",
    "SSL_SERVER_S_DN_S",
    "SSL_SERVER_S_DN_D",
    "SSL_SERVER_S_DN_UID",
    "SSL_SERVER_S_DN_Email",
    "SSL_SERVER_I_DN",
    "SSL_SERVER_I_DN_C",
    "SSL_SERVER_I_DN_ST",
    "SSL_SERVER_I_DN_L",
    "SSL_SERVER_I_DN_O",
    "SSL_SERVER_I_DN_OU",
    "SSL_SERVER_I_DN_CN",
    "SSL_SERVER_I_DN_T",
    "SSL_SERVER_I_DN_I",
    "SSL_SERVER_I_DN_G",
    "SSL_SERVER_I_DN_S",
    "SSL_SERVER_I_DN_D",
    "SSL_SERVER_I_DN_UID",
    "SSL_SERVER_I_DN_Email",
    "SSL_SERVER_A_KEY",
    "SSL_SERVER_A_SIG",
    "SSL_SESSION_ID",
    NULL
};

int nss_hook_Fixup(request_rec *r)
{
    SSLConnRec *sslconn = myConnConfig(r->connection);
    SSLSrvConfigRec *sc = mySrvConfig(r->server);
    SSLDirConfigRec *dc = myDirConfig(r);
    PRFileDesc * ssl;
    apr_table_t *env = r->subprocess_env;
    char *var, *val = "";
    int i;
    CERTCertificate *cert;
    CERTCertificateList *chain = NULL;

    /*
     * Check to see if SSL is on
     */
    if (!(sc->enabled && sslconn && (ssl = sslconn->ssl))) {
        return DECLINED;
    }

    /*
     * Set r->user if requested
     */
    if (dc->szUserName) {
        val = nss_var_lookup(r->pool, r->server, r->connection,
                             r, (char *)dc->szUserName);
        if (val && val[0]) {
            r->user = val;
        }
    }

    /*
     * Annotate the SSI/CGI environment with standard SSL information
     */
    /* the always present HTTPS (=HTTP over SSL) flag! */
    apr_table_setn(env, "HTTPS", "on");

    /* standard SSL environment variables */
    if (dc->nOptions & SSL_OPT_STDENVVARS) {
        for (i = 0; nss_hook_Fixup_vars[i]; i++) {
            var = (char *)nss_hook_Fixup_vars[i];
            val = nss_var_lookup(r->pool, r->server, r->connection, r, var);
            if (!strIsEmpty(val)) {
                apr_table_setn(env, var, val);
            }
        }
    }

    /*
     * On-demand bloat up the SSI/CGI environment with certificate data
     */
    if (dc->nOptions & SSL_OPT_EXPORTCERTDATA) {
        val = nss_var_lookup(r->pool, r->server, r->connection,
                             r, "SSL_SERVER_CERT");

        apr_table_setn(env, "SSL_SERVER_CERT", val);

        val = nss_var_lookup(r->pool, r->server, r->connection,
                             r, "SSL_CLIENT_CERT");

        apr_table_setn(env, "SSL_CLIENT_CERT", val);

        
        /* Need to fetch the entire SSL cert chain and add it to the 
         * variable SSL_CLIENT_CERT_CHAIN_[0..n]
         */
        cert = SSL_PeerCertificate(ssl);

        if (cert)
            chain = CERT_CertChainFromCert(cert, certUsageSSLClient, PR_TRUE);

        if (cert && chain) {
            int n;

            n = chain->len;

            CERT_DestroyCertificateList(chain);

            for (i = 0; i < n; i++) {
                var = apr_psprintf(r->pool, "SSL_CLIENT_CERT_CHAIN_%d", i);
                val = nss_var_lookup(r->pool, r->server, r->connection,
                                     r, var);
                if (val) {
                    apr_table_setn(env, var, val);
                }
            }
        }
        if (cert)
            CERT_DestroyCertificate(cert);
    }

    return DECLINED;
}

static void HandshakeDone(PRFileDesc *fd, void *doneflag)
{
    /*
     * This routine is called by SSL when the handshake is
     * complete. It sets local state so that the loop doing
     * reads from the socket can exit.
     */
    *((int *)doneflag) = 1;
}
