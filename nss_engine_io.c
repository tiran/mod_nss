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
**  I/O Hooks
**  _________________________________________________________________
*/

/* This file is designed to be the bridge between OpenSSL and httpd.
 * However, we really don't expect anyone (let alone ourselves) to
 * remember what is in this file.  So, first, a quick overview.
 *
 * In this file, you will find:
 * - nss_io_filter_input    (Apache input filter)
 * - nss_io_filter_output   (Apache output filter)
 *
 * - bio_filter_in_*        (OpenSSL input filter)
 * - nspr_filter_out_*       (OpenSSL output filter)
 *
 * The input chain is roughly:
 *
 * nss_io_filter_input->nss_io_input_read->SSL_read->...
 * ...->bio_filter_in_read->ap_get_brigade/next-httpd-filter
 *
 * In mortal terminology, we do the following:
 * - Receive a request for data to the SSL input filter
 * - Call a helper function once we know we should perform a read
 * - Call OpenSSL's SSL_read()
 * - SSL_read() will then call bio_filter_in_read
 * - bio_filter_in_read will then try to fetch data from the next httpd filter
 * - bio_filter_in_read will flatten that data and return it to SSL_read
 * - SSL_read will then decrypt the data
 * - nss_io_input_read will then receive decrypted data as a char* and
 *   ensure that there were no read errors
 * - The char* is placed in a brigade and returned
 *
 * Since connection-level input filters in httpd need to be able to
 * handle AP_MODE_GETLINE calls (namely identifying LF-terminated strings),
 * nss_io_input_getline which will handle this special case.
 *
 * Due to AP_MODE_GETLINE and AP_MODE_SPECULATIVE, we may sometimes have
 * 'leftover' decoded data which must be setaside for the next read.  That
 * is currently handled by the char_buffer_{read|write} functions.  So,
 * nss_io_input_read may be able to fulfill reads without invoking
 * SSL_read().
 *
 * Note that the filter context of nss_io_filter_input and bio_filter_in_*
 * are shared as bio_filter_in_ctx_t.
 *
 * Note that the filter is by choice limited to reading at most
 * AP_IOBUFSIZE (8192 bytes) per call.
 *
 */

/* Private structures */
typedef struct nspr_filter_in_ctx_t nspr_filter_in_ctx_t;
typedef struct nspr_filter_out_ctx_t nspr_filter_out_ctx_t;

typedef struct {
    PRFileDesc         *pssl;
    conn_rec           *c;
    ap_filter_t        *pInputFilter;
    ap_filter_t        *pOutputFilter;
    nspr_filter_in_ctx_t *inctx;
    nspr_filter_out_ctx_t *outctx;
    int                nobuffer; /* non-zero to prevent buffering */
} nss_filter_ctx_t;

typedef struct {
    int length;
    char *value;
} char_buffer_t;

struct nspr_filter_out_ctx_t {
    nss_filter_ctx_t *filter_ctx;
    apr_bucket_brigade *bb;
    apr_size_t length;
    char buffer[AP_IOBUFSIZE];
    apr_size_t blen;
    apr_status_t rc;
};

struct nspr_filter_in_ctx_t {
    ap_filter_t *f;
    apr_status_t rc;
    ap_input_mode_t mode;
    apr_read_type_e block;
    apr_bucket_brigade *bb;
    char_buffer_t cbuf;
    apr_pool_t *pool;
    char buffer[AP_IOBUFSIZE];
    nss_filter_ctx_t *filter_ctx;
};

/* Global variables for the NSPR I/O layer */
static PRDescIdentity    gIdentity = PR_INVALID_IO_LAYER;
static PRIOMethods       gMethods;

/*
 * this char_buffer api might seem silly, but we don't need to copy
 * any of this data and we need to remember the length.
 */
static int char_buffer_read(char_buffer_t *buffer, char *in, int inl)
{
    if (!buffer->length) {
        return 0;
    }

    if (buffer->length > inl) {
        /* we have have enough to fill the caller's buffer */
        memcpy(in, buffer->value, inl);
        buffer->value += inl;
        buffer->length -= inl;
    }
    else {
        /* swallow remainder of the buffer */
        memcpy(in, buffer->value, buffer->length);
        inl = buffer->length;
        buffer->value = NULL;
        buffer->length = 0;
    }

    return inl;
}

static int char_buffer_write(char_buffer_t *buffer, char *in, int inl)
{
    buffer->value = in;
    buffer->length = inl;
    return inl;
}

/* This function will read from a brigade and discard the read buckets as it
 * proceeds.  It will read at most *len bytes.
 */
static apr_status_t brigade_consume(apr_bucket_brigade *bb,
                                    apr_read_type_e block,
                                    char *c, apr_size_t *len)
{
    apr_size_t actual = 0;
    apr_status_t status = APR_SUCCESS;

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *b = APR_BRIGADE_FIRST(bb);
        const char *str;
        apr_size_t str_len;
        apr_size_t consume;

        /* Justin points out this is an http-ism that might
         * not fit if brigade_consume is added to APR.  Perhaps
         * apr_bucket_read(eos_bucket) should return APR_EOF?
         * Then this becomes mainline instead of a one-off.
         */
        if (APR_BUCKET_IS_EOS(b)) {
            status = APR_EOF;
            break;
        }

        /* The reason I'm not offering brigade_consume yet
         * across to apr-util is that the following call
         * illustrates how borked that API really is.  For
         * this sort of case (caller provided buffer) it
         * would be much more trivial for apr_bucket_consume
         * to do all the work that follows, based on the
         * particular characteristics of the bucket we are
         * consuming here.
         */
        status = apr_bucket_read(b, &str, &str_len, block);

        if (status != APR_SUCCESS) {
            if (APR_STATUS_IS_EOF(status)) {
                /* This stream bucket was consumed */
                apr_bucket_delete(b);
                continue;
            }
            break;
        }

        if (str_len > 0) {
            /* Do not block once some data has been consumed */
            block = APR_NONBLOCK_READ;

            /* Assure we don't overflow. */
            consume = (str_len + actual > *len) ? *len - actual : str_len;

            memcpy(c, str, consume);

            c += consume;
            actual += consume;

            if (consume >= b->length) {
                /* This physical bucket was consumed */
                apr_bucket_delete(b);
            }
            else {
                /* Only part of this physical bucket was consumed */
                b->start += consume;
                b->length -= consume;
            }
        }
        else if (b->length == 0) {
            apr_bucket_delete(b);
        }

        /* This could probably be actual == *len, but be safe from stray
         * photons. */
        if (actual >= *len) {
            break;
        }
    }

    *len = actual;
    return status;
}

/*
 * this is the function called by PR_Read()
 */
static PRInt32 PR_CALLBACK
nspr_filter_in_read(PRFileDesc *fd, void *in, PRInt32 inlen)
{
    apr_size_t inl = inlen;
    nss_filter_ctx_t *filter_ctx = (nss_filter_ctx_t *)(fd->secret);
    nspr_filter_in_ctx_t *inctx = filter_ctx->inctx;
    apr_read_type_e block = inctx->block;

    inctx->rc = APR_SUCCESS;

    /* mod_ssl catches this case, so should we. */
    if (!in)
        return 0;

    if (!inctx->bb) {
        inctx->rc = APR_EOF;
        return -1;
    }

    if (APR_BRIGADE_EMPTY(inctx->bb)) {
        inctx->rc = ap_get_brigade(inctx->f->next, inctx->bb,
                                   AP_MODE_READBYTES, block,
                                   inl);

        /* Not a problem, there was simply no data ready yet.
         */
        if (APR_STATUS_IS_EAGAIN(inctx->rc) || APR_STATUS_IS_EINTR(inctx->rc)
               || (inctx->rc == APR_SUCCESS && APR_BRIGADE_EMPTY(inctx->bb))) {
            PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
            return -1;
        }

        if (inctx->rc != APR_SUCCESS) {
            /* Unexpected errors discard the brigade */
            apr_brigade_cleanup(inctx->bb);
            inctx->bb = NULL;
            return -1;
        }
    }
    inctx->rc = brigade_consume(inctx->bb, block, in, &inl);

    if (inctx->rc == APR_SUCCESS) {
        return (int)inl;
    }

    if (APR_STATUS_IS_EAGAIN(inctx->rc)
            || APR_STATUS_IS_EINTR(inctx->rc)) {
        PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
        return (int)inl;
    }

    /* Unexpected errors and APR_EOF clean out the brigade.
     * Subsequent calls will return APR_EOF.
     */
    apr_brigade_cleanup(inctx->bb);
    inctx->bb = NULL;

    if (APR_STATUS_IS_EOF(inctx->rc) && inl) {
        /* Provide the results of this read pass,
         * without resetting the BIO retry_read flag
         */
        return (int)inl;
    }

    return -1;
}

static apr_status_t nss_io_input_read(nspr_filter_in_ctx_t *inctx,
                                      char *buf,
                                      apr_size_t *len)
{
    apr_size_t wanted = *len;
    apr_size_t bytes = 0;
    int rc;
    conn_rec *c = inctx->filter_ctx->c;

    *len = 0;

    /* If we have something leftover from last time, try that first. */
    if ((bytes = char_buffer_read(&inctx->cbuf, buf, wanted))) {
        *len = bytes;
        if (inctx->mode == AP_MODE_SPECULATIVE) {
            /* We want to rollback this read. */
            if (inctx->cbuf.length > 0) {
                inctx->cbuf.value -= bytes;
                inctx->cbuf.length += bytes;
            } else {
                char_buffer_write(&inctx->cbuf, buf, (int)bytes);
            }
            return APR_SUCCESS;
        }
        /* This could probably be *len == wanted, but be safe from stray
         * photons.
         */
        if (*len >= wanted) {
            return APR_SUCCESS;
        }
        if (inctx->mode == AP_MODE_GETLINE) {
            if (memchr(buf, APR_ASCII_LF, *len)) {
                return APR_SUCCESS;
            }
        }
        else {
            /* Down to a nonblock pattern as we have some data already
             */
            inctx->block = APR_NONBLOCK_READ;
        }
    }
    while (1) {

        if (!inctx->filter_ctx->pssl) {
            /* Ensure a non-zero error code is returned */
            if (inctx->rc == APR_SUCCESS) {
                inctx->rc = APR_EGENERAL;
            }
            break;
        }

        PR_SetError(0, 0);
        rc = PR_Read(inctx->filter_ctx->pssl, buf + bytes, wanted - bytes);

        if (rc > 0) {
            *len += rc;
            if (inctx->mode == AP_MODE_SPECULATIVE) {
                /* We want to rollback this read. */
                char_buffer_write(&inctx->cbuf, buf, rc);
            }
            return inctx->rc;
        }
        else if (rc == 0) {
            /* If EAGAIN, we will loop given a blocking read,
             * otherwise consider ourselves at EOF.
             */
            if (APR_STATUS_IS_EAGAIN(inctx->rc)
                    || APR_STATUS_IS_EINTR(inctx->rc)) {
                /* Already read something, return APR_SUCCESS instead.
                 * On win32 in particular, but perhaps on other kernels,
                 * a blocking call isn't 'always' blocking.
                 */
                if (*len > 0) {
                    inctx->rc = APR_SUCCESS;
                    break;
                }
                if (inctx->block == APR_NONBLOCK_READ) {
                    break;
                }
            }
            else {
                if (*len > 0) {
                    inctx->rc = APR_SUCCESS;
                }
                else {
                    inctx->rc = APR_EOF;
                }
                break;
            }
        }
        else /* (rc < 0) */ {
            int nss_err = PR_GetError();

            if (nss_err == PR_WOULD_BLOCK_ERROR) {
                /*
                 * If NSPR wants to read more, and we were nonblocking,
                 * report as an EAGAIN.  Otherwise loop, pulling more
                 * data from network filter.
                 *
                 * (This is usually the case when the client forces an SSL
                 * renegotation which is handled implicitly by NSS.)
                 */
                inctx->rc = APR_EAGAIN;

                if (*len > 0) {
                    inctx->rc = APR_SUCCESS;
                    break;
                }
                if (inctx->block == APR_NONBLOCK_READ) {
                    break;
                }
                continue;  /* Blocking and nothing yet?  Try again. */
            }
            else if (nss_err != 0) {
                if (APR_STATUS_IS_EAGAIN(inctx->rc)
                        || APR_STATUS_IS_EINTR(inctx->rc)) {
                    /* Already read something, return APR_SUCCESS instead. */
                    if (*len > 0) { 
                        inctx->rc = APR_SUCCESS;
                        break;
                    }
                    if (inctx->block == APR_NONBLOCK_READ) {
                        break;
                    }
                    continue;  /* Blocking and nothing yet?  Try again. */
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_INFO, inctx->rc, c->base_server,
                                "SSL input filter read failed.");
                    if (inctx->rc == 0)
                        nss_log_nss_error(APLOG_MARK, APLOG_ERR, c->base_server);
                }
            }
            if (inctx->rc == APR_SUCCESS) {
                inctx->rc = APR_EGENERAL;
            }
            break;
        }
    }
    return inctx->rc;
}

static apr_status_t nss_io_input_getline(nspr_filter_in_ctx_t *inctx,
                                         char *buf,
                                         apr_size_t *len)
{
    const char *pos = NULL;
    apr_status_t status;
    apr_size_t tmplen = *len, buflen = *len, offset = 0;

    *len = 0;

    /*
     * in most cases we get all the headers on the first SSL_read.
     * however, in certain cases SSL_read will only get a partial
     * chunk of the headers, so we try to read until LF is seen.
     */

    while (tmplen > 0) {
        status = nss_io_input_read(inctx, buf + offset, &tmplen);
     
        if (status != APR_SUCCESS) {
            return status;
        }

        *len += tmplen;

        if ((pos = memchr(buf, APR_ASCII_LF, *len))) {
            break;
        }

        offset += tmplen;
        tmplen = buflen - offset;
    }

    if (pos) {
        char *value;
        int length;
        apr_size_t bytes = pos - buf;


        bytes += 1;
        value = buf + bytes;
        length = *len - bytes;

        char_buffer_write(&inctx->cbuf, value, length);

        *len = bytes;
    }

    return APR_SUCCESS;
}

static apr_status_t nss_filter_write(ap_filter_t *f,
                                     const char *data,
                                     apr_size_t len)
{
    nss_filter_ctx_t *filter_ctx = f->ctx;
    nspr_filter_out_ctx_t *outctx;
    int res;

    /* write SSL */
    if (filter_ctx->pssl == NULL) {
        return APR_EGENERAL;
    }

    outctx = filter_ctx->outctx;

    res = PR_Write(filter_ctx->pssl, (char *)data, len);

    if (res < 0) {
        int nss_err = PR_GetError();

        if (nss_err == PR_WOULD_BLOCK_ERROR) {
            /*
             * If NSS wants to write more, and we were nonblocking,
             * report as an EAGAIN.  Otherwise loop, pushing more
             * data at the network filter.
             *
             * (This is usually the case when the client forces an SSL
             * renegotation which is handled implicitly by OpenSSL.)
             */
            outctx->rc = APR_EAGAIN;
        }
        else {
            conn_rec *c = f->c;
            /*
             * Log SSL errors
             */
            ap_log_error(APLOG_MARK, APLOG_INFO, outctx->rc, c->base_server,
                         "SSL library error %d writing data", nss_err);
            nss_log_nss_error(APLOG_MARK, APLOG_INFO, c->base_server);
        }
        if (outctx->rc == APR_SUCCESS) {
            outctx->rc = APR_EGENERAL;
        }
    }
    else if ((apr_size_t)res != len) {
        conn_rec *c = f->c;
        char *reason = "reason unknown";

        ap_log_error(APLOG_MARK, APLOG_INFO, outctx->rc, c->base_server,
                     "failed to write %d of %d bytes (%s)",
                     len - (apr_size_t)res, len, reason);

        outctx->rc = APR_EGENERAL;
    }
    return outctx->rc;
}

/* Just use a simple request.  Any request will work for this, because
 * we use a flag in the conn_rec->conn_vector now.  The fake request just
 * gets the request back to the Apache core so that a response can be sent.
 * 
 * To avoid calling back for more data from the socket, use an HTTP/0.9
 * request, and tack on an EOS bucket.
 */
#define HTTP_ON_HTTPS_PORT \
    "GET /" CRLF
 
#define HTTP_ON_HTTPS_PORT_BUCKET(alloc) \
    apr_bucket_immortal_create(HTTP_ON_HTTPS_PORT, \
                               sizeof(HTTP_ON_HTTPS_PORT) - 1, \
                               alloc)


static void nss_io_filter_disable(SSLConnRec *sslconn, ap_filter_t *f)
{
    nspr_filter_in_ctx_t *inctx = f->ctx;
    sslconn->ssl = NULL;
    inctx->filter_ctx->pssl = NULL;
}   

static apr_status_t nss_io_filter_error(ap_filter_t *f,
                                        apr_bucket_brigade *bb,
                                        apr_status_t status)
{   
    SSLConnRec *sslconn = myConnConfig(f->c);
    apr_bucket *bucket;
    
    switch (status) {
      case HTTP_BAD_REQUEST:
            /* log the situation */
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, f->c->base_server,
                         "SSL handshake failed: HTTP spoken on HTTPS port; "
                         "trying to send HTML error page");

            sslconn->non_nss_request = 1;
            nss_io_filter_disable(sslconn, f);

            /* fake the request line */
            bucket = HTTP_ON_HTTPS_PORT_BUCKET(f->c->bucket_alloc);
            break;

      default:
        return status;
    }

    APR_BRIGADE_INSERT_TAIL(bb, bucket);
    bucket = apr_bucket_eos_create(f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, bucket);

    return APR_SUCCESS;
}

static const char nss_io_filter[] = "NSS SSL/TLS Filter";
static const char nss_io_buffer[] = "NSS SSL/TLS Buffer";

static apr_status_t nss_filter_io_shutdown(nss_filter_ctx_t *filter_ctx,
                                           conn_rec *c,
                                           int abortive)
{
    PRFileDesc *ssl = filter_ctx->pssl;
    SSLConnRec *sslconn = myConnConfig(c);
     
    if (!ssl) {
        return APR_SUCCESS;
    }

    PR_Shutdown(ssl, PR_SHUTDOWN_SEND);
    PR_Close(ssl);

    /* log the fact that we've closed the connection */
    if (c->base_server->loglevel >= APLOG_INFO) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, c->base_server,
                     "Connection to child %ld closed "
                     "(server %s, client %s)",
                     c->id,
                     nss_util_vhostid(c->pool, c->base_server),
                     c->remote_ip ? c->remote_ip : "unknown");
    }

    /* deallocate the SSL connection */
    if (sslconn->client_cert) {
        CERT_DestroyCertificate(sslconn->client_cert);
        sslconn->client_cert = NULL;
    }

    sslconn->ssl = NULL;
    filter_ctx->pssl = NULL; /* so filters know we've been shutdown */

    if (abortive) {
        /* prevent any further I/O */
        c->aborted = 1;
    }

    return APR_SUCCESS;
}

static apr_status_t nss_io_filter_cleanup(void *data)
{
    nss_filter_ctx_t *filter_ctx = data;

    if (filter_ctx->pssl) {
        conn_rec *c = filter_ctx->c;
        SSLConnRec *sslconn = myConnConfig(c);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server,
                     "SSL connection destroyed without being closed");

        PR_Close(sslconn->ssl);
        sslconn->ssl = filter_ctx->pssl = NULL;
    }

    return APR_SUCCESS;
}

static apr_status_t nss_io_filter_input(ap_filter_t *f,
                                        apr_bucket_brigade *bb,
                                        ap_input_mode_t mode,
                                        apr_read_type_e block,
                                        apr_off_t readbytes)
{
    apr_status_t status;
    nspr_filter_in_ctx_t *inctx = f->ctx;

    apr_size_t len = sizeof(inctx->buffer);
    int is_init = (mode == AP_MODE_INIT);

    if (f->c->aborted) {
        /* XXX: Ok, if we aborted, we ARE at the EOS.  We also have
         * aborted.  This 'double protection' is probably redundant,
         * but also effective against just about anything.
         */
        apr_bucket *bucket = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
        return APR_ECONNABORTED;
    }

    if (!inctx->filter_ctx->pssl) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    /* XXX: we don't currently support anything other than these modes. */
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE &&
        mode != AP_MODE_SPECULATIVE && mode != AP_MODE_INIT) {
        return APR_ENOTIMPL;
    }

    inctx->mode = mode;
    inctx->block = block;

    if (is_init) {
        /* protocol module needs to handshake before sending
         * data to client (e.g. NNTP or FTP)
         */
        return APR_SUCCESS;
    }

    if (inctx->mode == AP_MODE_READBYTES ||
        inctx->mode == AP_MODE_SPECULATIVE) {
        /* Protected from truncation, readbytes < MAX_SIZE_T
         * FIXME: No, it's *not* protected.  -- jre */
        if (readbytes < len) {
            len = (apr_size_t)readbytes;
        }
        status = nss_io_input_read(inctx, inctx->buffer, &len);
    }
    else if (inctx->mode == AP_MODE_GETLINE) {
        status = nss_io_input_getline(inctx, inctx->buffer, &len);
    }
    else {
        /* We have no idea what you are talking about, so return an error. */
        return APR_ENOTIMPL;
    }

    if (status != APR_SUCCESS) {
        return nss_io_filter_error(f, bb, status);
    }

    /* Create a transient bucket out of the decrypted data. */
    if (len > 0) {
        apr_bucket *bucket =
            apr_bucket_transient_create(inctx->buffer, len, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, bucket);
    }

    return APR_SUCCESS;
}

static int nspr_filter_out_flush(nspr_filter_out_ctx_t *outctx)
{
    apr_bucket *e;

    if (!(outctx->blen || outctx->length)) {
        outctx->rc = APR_SUCCESS;
        return 1;
    }

    if (outctx->blen) {
        e = apr_bucket_transient_create(outctx->buffer, outctx->blen,
                                        outctx->bb->bucket_alloc);
        /* we filled this buffer first so add it to the
         * head of the brigade
         */
        APR_BRIGADE_INSERT_HEAD(outctx->bb, e);
        outctx->blen = 0;
    }

    outctx->length = 0;
    e = apr_bucket_flush_create(outctx->bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(outctx->bb, e);

    outctx->rc = ap_pass_brigade(outctx->filter_ctx->pOutputFilter->next,
                                 outctx->bb);
    if (outctx->rc == APR_SUCCESS && outctx->filter_ctx->c->aborted) {
        outctx->rc = APR_ECONNRESET;
    }
    return (outctx->rc == APR_SUCCESS) ? 1 : -1;
}

static PRInt32 PR_CALLBACK
nspr_filter_out_write(PRFileDesc *fd, const void *in, PRInt32 inl)
{
    nss_filter_ctx_t *filter_ctx = (nss_filter_ctx_t *)(fd->secret);
    nspr_filter_out_ctx_t *outctx = filter_ctx->outctx;

    /* pass along the encrypted data
     * need to flush since we're using SSL's malloc-ed buffer
     * which will be overwritten once we leave here
     */
    apr_bucket *bucket = apr_bucket_transient_create(in, inl,
                                         outctx->bb->bucket_alloc);

    outctx->length += inl;
    APR_BRIGADE_INSERT_TAIL(outctx->bb, bucket);

    if (nspr_filter_out_flush(outctx) < 0) {
        return -1;
    }

    return inl;
}

static apr_status_t nss_io_filter_output(ap_filter_t *f,
                                         apr_bucket_brigade *bb)
{
    apr_status_t status = APR_SUCCESS;
    nss_filter_ctx_t *filter_ctx = f->ctx;
    nspr_filter_in_ctx_t *inctx;
    nspr_filter_out_ctx_t *outctx;
    apr_read_type_e rblock = APR_NONBLOCK_READ;

    if (f->c->aborted) {
        apr_brigade_cleanup(bb);
        return APR_ECONNABORTED;
    }

    if (!filter_ctx->pssl) {
        /* nss_filter_io_shutdown was called */
        return ap_pass_brigade(f->next, bb);
    }

    inctx = filter_ctx->inctx;
    outctx = filter_ctx->outctx;

    /* When we are the writer, we must initialize the inctx
     * mode so that we block for any required ssl input, because
     * output filtering is always nonblocking.
     */
    inctx->mode = AP_MODE_READBYTES;
    inctx->block = APR_BLOCK_READ;

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *bucket = APR_BRIGADE_FIRST(bb);

        /* If it is a flush or EOS, we need to pass this down.
         * These types do not require translation by OpenSSL.
         */
        if (APR_BUCKET_IS_EOS(bucket) || APR_BUCKET_IS_FLUSH(bucket)) {
            if (nspr_filter_out_flush(filter_ctx->outctx) < 0) {
                status = outctx->rc;
                break;
            }

            if (APR_BUCKET_IS_EOS(bucket)) {
                /*
                 * By definition, nothing can come after EOS.
                 * which also means we can pass the rest of this brigade
                 * without creating a new one since it only contains the
                 * EOS bucket.
                 */

                if ((status = ap_pass_brigade(f->next, bb)) != APR_SUCCESS) {
                    return status;
                }
                break;
            }
            else {
                /* nspr_filter_out_flush() already passed down a flush bucket
                 * if there was any data to be flushed.
                 */
                apr_bucket_delete(bucket);
            }
        }
#if defined AP_BUCKET_IS_EOC
        else if (AP_BUCKET_IS_EOC(bucket)) {
            /* The special "EOC" bucket means a shutdown is needed;
             * - turn off buffering in nspr_filter_out_write
             * - issue the SSL_shutdown
             */
            filter_ctx->nobuffer = 1;
            status = nss_filter_io_shutdown(filter_ctx, f->c, 0);
            if (status != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_INFO, status, f->c->base_server,
                             "SSL filter error shutting down I/O");
            }
            if ((status = ap_pass_brigade(f->next, bb)) != APR_SUCCESS) {
                return status;
            }
            break;
        }
#endif
        else {
            /* filter output */
            const char *data;
            apr_size_t len;

            status = apr_bucket_read(bucket, &data, &len, rblock);

            if (APR_STATUS_IS_EAGAIN(status)) {
                /* No data available: flush... */
                if (nspr_filter_out_flush(filter_ctx->outctx) < 0) {
                    status = outctx->rc;
                    break;
                }
                rblock = APR_BLOCK_READ;
                continue; /* and try again with a blocking read. */
            }

            rblock = APR_NONBLOCK_READ;

            if (!APR_STATUS_IS_EOF(status) && (status != APR_SUCCESS)) {
                break;
            }

            status = nss_filter_write(f, data, len);
            apr_bucket_delete(bucket);

            if (status != APR_SUCCESS) {
                break;
            }
        }
    }
    return status;
}

static void nss_io_output_create(nss_filter_ctx_t *filter_ctx, conn_rec *c)
{
    nspr_filter_out_ctx_t *outctx = apr_palloc(c->pool, sizeof(*outctx));

    outctx->filter_ctx = filter_ctx;
    outctx->bb = apr_brigade_create(c->pool, c->bucket_alloc);
    outctx->blen = 0;
    outctx->length = 0;

    filter_ctx->outctx = outctx;

    return;
}

/* 128K maximum buffer size by default. */
#ifndef SSL_MAX_IO_BUFFER
#define SSL_MAX_IO_BUFFER (128 * 1024)
#endif

struct modnss_buffer_ctx {
    apr_bucket_brigade *bb;
    apr_pool_t *pool;
};

int nss_io_buffer_fill(request_rec *r)
{
    conn_rec *c = r->connection;
    struct modnss_buffer_ctx *ctx;
    apr_bucket_brigade *tempb;
    apr_off_t total = 0; /* total length buffered */
    int eos = 0; /* non-zero once EOS is seen */
    
    /* Create the context which will be passed to the input filter. */
    ctx = apr_palloc(r->pool, sizeof *ctx);
    apr_pool_create(&ctx->pool, r->pool);
    ctx->bb = apr_brigade_create(ctx->pool, c->bucket_alloc);

    /* ... and a temporary brigade. */
    tempb = apr_brigade_create(r->pool, c->bucket_alloc);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "filling buffer");

    do {
        apr_status_t rv;
        apr_bucket *e, *next;

        /* The request body is read from the protocol-level input
         * filters; the buffering filter will reinject it from that
         * level, allowing content/resource filters to run later, if
         * necessary. */

        rv = ap_get_brigade(r->proto_input_filters, tempb, AP_MODE_READBYTES,
                            APR_BLOCK_READ, 8192);
        if (rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "could not read request body for SSL buffer");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        
        /* Iterate through the returned brigade: setaside each bucket
         * into the context's pool and move it into the brigade. */
        for (e = APR_BRIGADE_FIRST(tempb); 
             e != APR_BRIGADE_SENTINEL(tempb) && !eos; e = next) {
            const char *data;
            apr_size_t len;

            next = APR_BUCKET_NEXT(e);

            if (APR_BUCKET_IS_EOS(e)) {
                eos = 1;
            } else if (!APR_BUCKET_IS_METADATA(e)) {
                rv = apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
                if (rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                  "could not read bucket for SSL buffer");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                total += len;
            }
                
            rv = apr_bucket_setaside(e, ctx->pool);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              "could not setaside bucket for SSL buffer");
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
        }

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                      "total of %" APR_OFF_T_FMT " bytes in buffer, eos=%d",
                      total, eos);

        /* Fail if this exceeds the maximum buffer size. */
        if (total > SSL_MAX_IO_BUFFER) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "request body exceeds maximum size for SSL buffer");
            return HTTP_REQUEST_ENTITY_TOO_LARGE;
        }

    } while (!eos);

    apr_brigade_destroy(tempb);

    /* Insert the filter which will supply the buffered data. */
    ap_add_input_filter(nss_io_buffer, ctx, r, c);

    return 0;
}

/* This input filter supplies the buffered request body to the caller
 * from the brigade stored in f->ctx. */
static apr_status_t nss_io_filter_buffer(ap_filter_t *f,
                                         apr_bucket_brigade *bb,
                                         ap_input_mode_t mode,
                                         apr_read_type_e block,
                                         apr_off_t bytes)
{
    struct modnss_buffer_ctx *ctx = f->ctx;
    apr_status_t rv;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
                  "read from buffered SSL brigade, mode %d, "
                  "%" APR_OFF_T_FMT " bytes",
                  mode, bytes);

    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE) {
        return APR_ENOTIMPL;
    }

    if (mode == AP_MODE_READBYTES) {
        apr_bucket *e;

        /* Partition the buffered brigade. */
        rv = apr_brigade_partition(ctx->bb, bytes, &e);
        if (rv && rv != APR_INCOMPLETE) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                          "could not partition buffered SSL brigade");
            ap_remove_input_filter(f);
            return rv;
        }

        /* If the buffered brigade contains less then the requested
         * length, just pass it all back. */
        if (rv == APR_INCOMPLETE) {
            APR_BRIGADE_CONCAT(bb, ctx->bb);
        } else {
            apr_bucket *d = APR_BRIGADE_FIRST(ctx->bb);

            e = APR_BUCKET_PREV(e);
            
            /* Unsplice the partitioned segment and move it into the
             * passed-in brigade; no convenient way to do this with
             * the APR_BRIGADE_* macros. */
            APR_RING_UNSPLICE(d, e, link);
            APR_RING_SPLICE_HEAD(&bb->list, d, e, apr_bucket, link);

            APR_BRIGADE_CHECK_CONSISTENCY(bb);
            APR_BRIGADE_CHECK_CONSISTENCY(ctx->bb);
        }
    }
    else {
        /* Split a line into the passed-in brigade. */
        rv = apr_brigade_split_line(bb, ctx->bb, mode, bytes);

        if (rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                          "could not split line from buffered SSL brigade");
            ap_remove_input_filter(f);
            return rv;
        }
    }

    if (APR_BRIGADE_EMPTY(ctx->bb)) {
        apr_bucket *e = APR_BRIGADE_LAST(bb);
        
        /* Ensure that the brigade is terminated by an EOS if the
         * buffered request body has been entirely consumed. */
        if (e == APR_BRIGADE_SENTINEL(bb) || !APR_BUCKET_IS_EOS(e)) {
            e = apr_bucket_eos_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
        }

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
                      "buffered SSL brigade now exhausted; removing filter");
        ap_remove_input_filter(f);
    }

    return APR_SUCCESS;
}

static void nss_io_input_add_filter(nss_filter_ctx_t *filter_ctx, conn_rec *c,
                                    PRFileDesc *ssl)
{
    nspr_filter_in_ctx_t *inctx;

    inctx = apr_palloc(c->pool, sizeof(*inctx));

    filter_ctx->pInputFilter = ap_add_input_filter(nss_io_filter, inctx, NULL, c);

    inctx->f = filter_ctx->pInputFilter;
    inctx->rc = APR_SUCCESS;
    inctx->mode = AP_MODE_READBYTES;
    inctx->cbuf.length = 0;
    inctx->bb = apr_brigade_create(c->pool, c->bucket_alloc);
    inctx->block = APR_BLOCK_READ;
    inctx->pool = c->pool;
    inctx->filter_ctx = filter_ctx;

    filter_ctx->inctx = inctx;
}

void nss_io_filter_init(conn_rec *c, PRFileDesc *ssl)
{
    nss_filter_ctx_t *filter_ctx;

    filter_ctx = apr_palloc(c->pool, sizeof(nss_filter_ctx_t));
    filter_ctx->pOutputFilter   = ap_add_output_filter(nss_io_filter,
                                                   filter_ctx, NULL, c);

    nss_io_input_add_filter(filter_ctx, c, ssl);
    nss_io_output_create(filter_ctx, c);

    filter_ctx->pssl = ssl;
    filter_ctx->c = c;
    ssl->lower->secret = (PRFilePrivate *)filter_ctx;

    apr_pool_cleanup_register(c->pool, (void*)filter_ctx,
                              nss_io_filter_cleanup, apr_pool_cleanup_null);

    return;
}

void nss_io_filter_register(apr_pool_t *p)
{
    ap_register_input_filter  (nss_io_filter, nss_io_filter_input,  NULL, AP_FTYPE_CONNECTION + 5);
    ap_register_output_filter (nss_io_filter, nss_io_filter_output, NULL, AP_FTYPE_CONNECTION + 5);  
    ap_register_input_filter  (nss_io_buffer, nss_io_filter_buffer, NULL, AP_FTYPE_PROTOCOL - 1);
    return; 
}

PRFileDesc * nss_io_new_fd() {
    PRFileDesc *ssl = PR_CreateIOLayerStub(gIdentity, &gMethods);

    return ssl;
}

static PRStatus PR_CALLBACK nspr_filter_getpeername(PRFileDesc *fd, PRNetAddr *addr) {
    nss_filter_ctx_t *filter_ctx;
    conn_rec *c;

    /* This can occur when doing SSL_ImportFD(NULL, something); */
    if (fd->secret == NULL)
        return PR_FAILURE;

    filter_ctx = (nss_filter_ctx_t *)(fd->secret);
    c = filter_ctx->c;

    return PR_StringToNetAddr(c->remote_ip, addr);
}

/* 
 * Translate NSPR PR_GetSocketOption() calls into apr_socket_opt_get() calls.
 */
static PRStatus PR_CALLBACK nspr_filter_getsocketoption(PRFileDesc *fd, PRSocketOptionData *data) {
    nss_filter_ctx_t *filter_ctx = (nss_filter_ctx_t *)(fd->secret);
    conn_rec *c = filter_ctx->c;
    SSLConnRec *sslconn = myConnConfig(c); /* for the Apache socket */
    apr_int32_t on;
    PRStatus rv = PR_FAILURE;

    switch(data->option) {
        case PR_SockOpt_Nonblocking:
            if (apr_socket_opt_get(sslconn->client_socket, APR_SO_NONBLOCK, &on) == APR_SUCCESS) {
                data->value.non_blocking = (on == 1) ? PR_TRUE : PR_FALSE;
                rv = PR_SUCCESS;
            }
            break;
        case PR_SockOpt_Linger:
            if (apr_socket_opt_get(sslconn->client_socket, APR_SO_LINGER, &on) == APR_SUCCESS) {
                data->value.linger.polarity = (on == 1) ? PR_TRUE : PR_FALSE;
                data->value.linger.linger = APR_MAX_SECS_TO_LINGER;
                rv = PR_SUCCESS;
            }
            break;
        case PR_SockOpt_NoDelay:
            if (apr_socket_opt_get(sslconn->client_socket, APR_TCP_NODELAY, &on) == APR_SUCCESS) {
                data->value.no_delay = (on == 1) ? PR_TRUE : PR_FALSE;
                rv = PR_SUCCESS;
            }
        case PR_SockOpt_Reuseaddr:
            if (apr_socket_opt_get(sslconn->client_socket, APR_SO_REUSEADDR, &on) == APR_SUCCESS) {
                data->value.reuse_addr = (on == 1) ? PR_TRUE : PR_FALSE;
                rv = PR_SUCCESS;
            }
            break;
        case PR_SockOpt_Keepalive: /* has separate #define in Apache, use it */
            if (apr_socket_opt_get(sslconn->client_socket, APR_SO_KEEPALIVE, &on) == APR_SUCCESS) {
                data->value.keep_alive = (on == 1) ? PR_TRUE : PR_FALSE;
                rv = PR_SUCCESS;
            }
            break;
        case PR_SockOpt_RecvBufferSize:
        case PR_SockOpt_SendBufferSize:
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server, "For sendbuffersize and recvbuffersize we can only see if they are on, not the value.");
            break;
        case PR_SockOpt_McastLoopback:
        case PR_SockOpt_MaxSegment:
        case PR_SockOpt_IpTimeToLive:
        case PR_SockOpt_IpTypeOfService:
        case PR_SockOpt_McastTimeToLive:
        case PR_SockOpt_McastInterface:
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, c->base_server, "Unsupported or socket option.");
            break;
        default:
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, c->base_server, "Unknown socket option.");
            break;
    }

    return rv;
}

/* 
 * Translate NSPR PR_SetSocketOption() calls into apr_socket_opt_set() calls.
 */
static PRStatus PR_CALLBACK nspr_filter_setsocketOption(PRFileDesc *fd, const PRSocketOptionData *data) {
    nss_filter_ctx_t *filter_ctx = (nss_filter_ctx_t *)(fd->secret);
    conn_rec *c = filter_ctx->c;
    SSLConnRec *sslconn = myConnConfig(c); /* for the Apache socket */
    PRStatus rv = PR_FAILURE;

    switch(data->option) {
        case PR_SockOpt_Nonblocking:
            if (apr_socket_opt_set(sslconn->client_socket, APR_SO_NONBLOCK, data->value.non_blocking) == APR_SUCCESS) {
                rv = PR_SUCCESS;
            }
            break;
        case PR_SockOpt_Linger:
            if (apr_socket_opt_set(sslconn->client_socket, APR_SO_LINGER, data->value.linger.polarity) == APR_SUCCESS) {
                rv = PR_SUCCESS;
            }
            break;
        case PR_SockOpt_NoDelay:
            if (apr_socket_opt_set(sslconn->client_socket, APR_TCP_NODELAY, data->value.no_delay) == APR_SUCCESS) {
                rv = PR_SUCCESS;
            }
        case PR_SockOpt_Reuseaddr:
            if (apr_socket_opt_set(sslconn->client_socket, APR_SO_REUSEADDR, data->value.reuse_addr) == APR_SUCCESS) {
                rv = PR_SUCCESS;
            }
            break;
        case PR_SockOpt_Keepalive: /* has separate #define in Apache, use it */
            if (apr_socket_opt_set(sslconn->client_socket, APR_SO_KEEPALIVE, data->value.keep_alive) == APR_SUCCESS) {
                rv = PR_SUCCESS;
            }
            break;
        case PR_SockOpt_RecvBufferSize:
            if (apr_socket_opt_set(sslconn->client_socket, APR_SO_RCVBUF, data->value.recv_buffer_size) == APR_SUCCESS) {
                rv = PR_SUCCESS;
            }
            break;
        case PR_SockOpt_SendBufferSize:
            if (apr_socket_opt_set(sslconn->client_socket, APR_SO_SNDBUF, data->value.send_buffer_size) == APR_SUCCESS) {
                rv = PR_SUCCESS;
            }
            break;
        case PR_SockOpt_McastLoopback:
        case PR_SockOpt_MaxSegment:
        case PR_SockOpt_IpTimeToLive:
        case PR_SockOpt_IpTypeOfService:
        case PR_SockOpt_McastTimeToLive:
        case PR_SockOpt_McastInterface:
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, c->base_server, "Unsupported or socket option.");
            break;
        default:
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, c->base_server, "Unknown socket option.");
            break;
    }

    return rv;
}

static PRStatus PR_CALLBACK
nspr_filter_shutdown(PRFileDesc *fd, PRIntn how) 
{
    return PR_SUCCESS;
}

static PRStatus PR_CALLBACK
nspr_filter_close(PRFileDesc *fd)
{
    return PR_SUCCESS;
}

/* Wrapper that ignores flags and timeouts */
static PRInt32 PR_CALLBACK nspr_filter_recv(PRFileDesc *fd, void *buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout) {
    return nspr_filter_in_read(fd, buf, amount);
}

/* Wrapper that ignores flags and timeouts */
static PRInt32 PR_CALLBACK nspr_filter_send(PRFileDesc *fd, const void *buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout) {
    return nspr_filter_out_write(fd, buf, amount);
}

/* 
 * Called once to initialize the NSPR layer that we push for each
 * request.
 */
int nss_io_layer_init()
{
    const PRIOMethods *defaultMethods;
    int rc = 1;

    if (gIdentity != PR_INVALID_IO_LAYER) {
        /* already initialized */
        return PR_FAILURE;
    }

    gIdentity = PR_GetUniqueIdentity("ApacheNSSLayer");

    if (gIdentity == PR_INVALID_IO_LAYER)
        return PR_FAILURE;

    defaultMethods = PR_GetDefaultIOMethods();

    if (defaultMethods == NULL)
        return PR_FAILURE;

    gMethods = *defaultMethods;

    gMethods.close           = nspr_filter_close;
    gMethods.read            = nspr_filter_in_read;
    gMethods.write           = nspr_filter_out_write;
    gMethods.recv            = nspr_filter_recv;
    gMethods.send            = nspr_filter_send;;
    gMethods.getpeername     = nspr_filter_getpeername;
    gMethods.shutdown        = nspr_filter_shutdown;
    gMethods.getsocketoption = nspr_filter_getsocketoption;
    gMethods.setsocketoption = nspr_filter_setsocketOption;

    return rc;
}

SECStatus
nss_AuthCertificate(void *arg, PRFileDesc *socket,
                  PRBool checksig, PRBool isServer)
{
    SECStatus           status;
    nss_filter_ctx_t   *filter_ctx;

    if (!arg || !socket) {
        return SECFailure;
    }

    filter_ctx = (nss_filter_ctx_t *)(socket->lower->secret);

    status = SSL_AuthCertificate(arg, socket, checksig, isServer);

    if (status == SECSuccess) {
        conn_rec *c = filter_ctx->c;
        SSLConnRec *sslconn = myConnConfig(c);

        sslconn->client_cert = SSL_PeerCertificate(socket);
        sslconn->client_dn = NULL;
    }

    return status;
}
