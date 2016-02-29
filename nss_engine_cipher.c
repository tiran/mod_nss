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
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sslproto.h>

/* ciphernum is defined in nss_engine_cipher.h */
cipher_properties ciphers_def[] =
{
    {"rsa_null_md5", TLS_RSA_WITH_NULL_MD5, "NULL-MD5", SSL_kRSA|SSL_aRSA|SSL_eNULL|SSL_MD5, SSLV3, SSL_STRONG_NONE, 0, 0},
    {"rsa_null_sha", TLS_RSA_WITH_NULL_SHA, "NULL-SHA", SSL_kRSA|SSL_aRSA|SSL_eNULL|SSL_SHA1, SSLV3, SSL_STRONG_NONE, 0, 0},
    {"rsa_rc4_40_md5", TLS_RSA_EXPORT_WITH_RC4_40_MD5, "EXP-RC4-MD5", SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5, SSLV3, SSL_EXPORT40, 40, 128},
    {"rsa_rc4_128_md5", TLS_RSA_WITH_RC4_128_MD5, "RC4-MD5", SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5, SSLV3, SSL_MEDIUM, 128, 128},
    {"rsa_rc4_128_sha", TLS_RSA_WITH_RC4_128_SHA, "RC4-SHA", SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_SHA1, SSLV3, SSL_MEDIUM, 128, 128},
    {"rsa_rc2_40_md5", TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, "EXP-RC2-CBC-MD5", SSL_kRSA|SSL_aRSA|SSL_RC2|SSL_MD5, SSLV3, SSL_EXPORT40, 40, 128},
    /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA not implemented 0x0008 */
    {"rsa_des_sha", TLS_RSA_WITH_DES_CBC_SHA, "DES-CBC-SHA", SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1, SSLV3, SSL_LOW, 56, 56},
    {"rsa_3des_sha", TLS_RSA_WITH_3DES_EDE_CBC_SHA, "DES-CBC3-SHA", SSL_kRSA|SSL_aRSA|SSL_3DES|SSL_SHA1, SSLV3, SSL_HIGH, 168, 168},
#ifdef ENABLE_SERVER_DHE
    {"dhe_rsa_des_sha", TLS_DHE_RSA_WITH_DES_CBC_SHA, "EDH-RSA-DES-CBC-SHA", SSL_kEDH|SSL_aRSA|SSL_DES|SSL_SHA1, SSLV3, SSL_LOW, 56, 56},
#endif
    {"rsa_aes_128_sha", TLS_RSA_WITH_AES_128_CBC_SHA, "AES128-SHA", SSL_kRSA|SSL_aRSA|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128},
    {"rsa_aes_256_sha", TLS_RSA_WITH_AES_256_CBC_SHA, "AES256-SHA", SSL_kRSA|SSL_aRSA|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256},
    {"null_sha_256", TLS_RSA_WITH_NULL_SHA256, "NULL-SHA256", SSL_kRSA|SSL_aRSA|SSL_eNULL|SSL_SHA256, TLSV1_2, SSL_STRONG_NONE, 0, 0},
    {"aes_128_sha_256", TLS_RSA_WITH_AES_128_CBC_SHA256, "AES128-SHA256", SSL_kRSA|SSL_aRSA|SSL_AES128|SSL_SHA256, TLSV1_2, SSL_HIGH, 128, 128},
    {"aes_256_sha_256", TLS_RSA_WITH_AES_256_CBC_SHA256, "AES256-SHA256", SSL_kRSA|SSL_aRSA|SSL_AES256|SSL_SHA256, TLSV1_2, SSL_HIGH, 256, 256},
    {"camelia_128_sha", TLS_RSA_WITH_CAMELLIA_128_CBC_SHA, "CAMELLIA128-SHA", SSL_kRSA|SSL_aRSA|SSL_CAMELLIA128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128},
    {"rsa_des_56_sha", TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA, "EXP1024-DES-CBC-SHA", SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1, TLSV1, SSL_EXPORT56, 56, 56},
    {"rsa_rc4_56_sha", TLS_RSA_EXPORT1024_WITH_RC4_56_SHA, "EXP1024-RC4-SHA", SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_SHA1, TLSV1, SSL_EXPORT56, 56, 128},
    {"camelia_256_sha", TLS_RSA_WITH_CAMELLIA_256_CBC_SHA, "CAMELLIA256-SHA", SSL_kRSA|SSL_aRSA|SSL_CAMELLIA256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256},
#ifdef ENABLE_GCM
    {"rsa_aes_128_gcm_sha_256", TLS_RSA_WITH_AES_128_GCM_SHA256, "AES128-GCM-SHA256", SSL_kRSA|SSL_aRSA|SSL_AES128GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 128, 128},
#endif
#ifdef ENABLE_SHA384
    {"rsa_aes_256_gcm_sha_384", TLS_RSA_WITH_AES_256_GCM_SHA384, "AES256-GCM-SHA384", SSL_kRSA|SSL_aRSA|SSL_AES256GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 256, 256},
#endif
    {"fips_3des_sha", SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA, "FIPS-DES-CBC3-SHA", SSL_kRSA|SSL_aRSA|SSL_3DES|SSL_SHA1, SSLV3, SSL_HIGH, 112, 168},
    {"fips_des_sha", SSL_RSA_FIPS_WITH_DES_CBC_SHA, "FIPS-DES-CBC-SHA", SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1, SSLV3, SSL_LOW, 56, 56},
#ifdef ENABLE_SERVER_DHE
    {"dhe_rsa_3des_sha", TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, "EDH-RSA-DES-CBC3-SHA", SSL_kEDH|SSL_aRSA|SSL_3DES|SSL_SHA1, TLSV1, SSL_HIGH, 112, 168},
    {"dhe_rsa_aes_128_sha", TLS_DHE_RSA_WITH_AES_128_CBC_SHA, "DHE-RSA-AES128-SHA", SSL_kEDH|SSL_aRSA|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128},
    {"dhe_rsa_aes_256_sha", TLS_DHE_RSA_WITH_AES_256_CBC_SHA, "DHE-RSA-AES256-SHA", SSL_kEDH|SSL_aRSA|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256},
    {"dhe_rsa_camellia_128_sha", TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA, "DHE-RSA-CAMELLIA128-SHA", SSL_kEDH|SSL_aRSA|SSL_CAMELLIA128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128},
    {"dhe_rsa_camellia_256_sha", TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA, "DHE-RSA-CAMELLIA256-SHA", SSL_kEDH|SSL_aRSA|SSL_CAMELLIA256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256},
    {"dhe_rsa_aes_128_sha256", TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, "DHE-RSA-AES128-SHA256", SSL_kEDH|SSL_aRSA|SSL_AES128|SSL_SHA256, TLSV1_2, SSL_HIGH, 128, 128},
    {"dhe_rsa_aes_256_sha256", TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, "DHE-RSA-AES256-SHA256", SSL_kEDH|SSL_aRSA|SSL_AES256|SSL_SHA256, TLSV1_2, SSL_HIGH, 256, 256},
#ifdef ENABLE_GCM
    {"dhe_rsa_aes_128_gcm_sha_256", TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, "DHE-RSA-AES128-GCM-SHA256", SSL_kEDH|SSL_aRSA|SSL_AES128GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 128, 128},
#endif
#ifdef ENABLE_SHA384
    {"dhe_rsa_aes_256_gcm_sha_384", TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, "DHE-RSA-AES256-GCM-SHA384", SSL_kEDH|SSL_aRSA|SSL_AES256GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 256, 256},
#endif
#endif /* ENABLE_SERVER_DHE */
#ifdef NSS_ENABLE_ECC
    {"ecdh_ecdsa_null_sha", TLS_ECDH_ECDSA_WITH_NULL_SHA, "ECDH-ECDSA-NULL-SHA", SSL_kECDHe|SSL_aECDH|SSL_eNULL|SSL_SHA1, TLSV1, SSL_STRONG_NONE, 0, 0},
    {"ecdh_ecdsa_rc4_128_sha", TLS_ECDH_ECDSA_WITH_RC4_128_SHA, "ECDH-ECDSA-RC4-SHA", SSL_kECDHe|SSL_aECDH|SSL_RC4|SSL_SHA1, TLSV1, SSL_MEDIUM, 128, 128},
    {"ecdh_ecdsa_3des_sha", TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, "ECDH-ECDSA-DES-CBC3-SHA", SSL_kECDHe|SSL_aECDH|SSL_3DES|SSL_SHA1, TLSV1, SSL_HIGH, 112, 168},
    {"ecdh_ecdsa_aes_128_sha", TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, "ECDH-ECDSA-AES128-SHA", SSL_kECDHe|SSL_aECDH|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128},
    {"ecdh_ecdsa_aes_256_sha", TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, "ECDH-ECDSA-AES256-SHA", SSL_kECDHe|SSL_aECDH|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256},
    {"ecdhe_ecdsa_null_sha", TLS_ECDHE_ECDSA_WITH_NULL_SHA, "ECDHE-ECDSA-NULL-SHA", SSL_kEECDH|SSL_aECDSA|SSL_eNULL|SSL_SHA1, TLSV1, SSL_STRONG_NONE, 0, 0},
    {"ecdhe_ecdsa_rc4_128_sha", TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, "ECDHE-ECDSA-RC4-SHA", SSL_kEECDH|SSL_aECDSA|SSL_RC4|SSL_SHA1, TLSV1, SSL_MEDIUM, 128, 128},
    {"ecdhe_ecdsa_3des_sha", TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, "ECDHE-ECDSA-DES-CBC3-SHA", SSL_kEECDH|SSL_aECDSA|SSL_3DES|SSL_SHA1, TLSV1, SSL_HIGH, 112, 168},
    {"ecdhe_ecdsa_aes_128_sha", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "ECDHE-ECDSA-AES128-SHA", SSL_kEECDH|SSL_aECDSA|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128},
    {"ecdhe_ecdsa_aes_256_sha", TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "ECDHE-ECDSA-AES256-SHA", SSL_kEECDH|SSL_aECDSA|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256},
    {"ecdh_rsa_null_sha", TLS_ECDH_RSA_WITH_NULL_SHA, "ECDH-RSA-NULL-SHA", SSL_kECDHr|SSL_aECDH|SSL_eNULL|SSL_SHA1, TLSV1, SSL_STRONG_NONE, 0, 0},
    {"ecdh_rsa_128_sha", TLS_ECDH_RSA_WITH_RC4_128_SHA, "ECDH-RSA-RC4-SHA", SSL_kECDHr|SSL_aECDH|SSL_RC4|SSL_SHA1, TLSV1, SSL_MEDIUM, 128, 128},
    {"ecdh_rsa_3des_sha", TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, "ECDH-RSA-DES-CBC3-SHA", SSL_kECDHr|SSL_aECDH|SSL_3DES|SSL_SHA1, TLSV1, SSL_HIGH, 112, 168},
    {"ecdh_rsa_aes_128_sha", TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, "ECDH-RSA-AES128-SHA", SSL_kECDHr|SSL_aECDH|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128},
    {"ecdh_rsa_aes_256_sha", TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, "ECDH-RSA-AES256-SHA", SSL_kECDHr|SSL_aECDH|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256},
    {"ecdhe_rsa_null", TLS_ECDHE_RSA_WITH_NULL_SHA, "ECDHE-RSA-NULL-SHA", SSL_kEECDH|SSL_aRSA|SSL_eNULL|SSL_SHA1, TLSV1, SSL_STRONG_NONE, 0, 0},
    {"ecdhe_rsa_rc4_128_sha", TLS_ECDHE_RSA_WITH_RC4_128_SHA, "ECDHE-RSA-RC4-SHA", SSL_kEECDH|SSL_aRSA|SSL_RC4|SSL_SHA1, TLSV1, SSL_MEDIUM, 128, 128},
    {"ecdhe_rsa_3des_sha", TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "ECDHE-RSA-DES-CBC3-SHA", SSL_kEECDH|SSL_aRSA|SSL_3DES|SSL_SHA1, TLSV1, SSL_HIGH, 112, 168},
    {"ecdhe_rsa_aes_128_sha", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "ECDHE-RSA-AES128-SHA", SSL_kEECDH|SSL_aRSA|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128},
    {"ecdhe_rsa_aes_256_sha", TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "ECDHE-RSA-AES256-SHA", SSL_kEECDH|SSL_aRSA|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256},
    {"ecdh_anon_null_sha", TLS_ECDH_anon_WITH_NULL_SHA, "AECDH-NULL-SHA", SSL_kEECDH|SSL_aNULL|SSL_eNULL|SSL_SHA1, TLSV1, SSL_STRONG_NONE, 0, 0},
    {"ecdh_anon_rc4_128sha", TLS_ECDH_anon_WITH_RC4_128_SHA, "AECDH-RC4-SHA", SSL_kEECDH|SSL_aNULL|SSL_RC4|SSL_SHA1, TLSV1, SSL_MEDIUM, 128, 128},
    {"ecdh_anon_3des_sha", TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, "AECDH-DES-CBC3-SHA", SSL_kEECDH|SSL_aNULL|SSL_3DES|SSL_SHA1, TLSV1, SSL_HIGH, 112, 168},
    {"ecdh_anon_aes_128_sha", TLS_ECDH_anon_WITH_AES_128_CBC_SHA, "AECDH-AES128-SHA", SSL_kEECDH|SSL_aNULL|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128},
    {"ecdh_anon_aes_256_sha", TLS_ECDH_anon_WITH_AES_256_CBC_SHA, "AECDH-AES256-SHA", SSL_kEECDH|SSL_aNULL|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256},
    {"ecdhe_ecdsa_aes_128_sha_256", TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "ECDHE-ECDSA-AES128-SHA256", SSL_kEECDH|SSL_aECDSA|SSL_AES128|SSL_SHA256, TLSV1_2, SSL_HIGH, 128, 128},
    {"ecdhe_rsa_aes_128_sha_256", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "ECDHE-RSA-AES128-SHA256", SSL_kEECDH|SSL_aRSA|SSL_AES128|SSL_SHA256, TLSV1_2, SSL_HIGH, 128, 128},
#ifdef ENABLE_GCM
    {"ecdhe_ecdsa_aes_128_gcm_sha_256", TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "ECDHE-ECDSA-AES128-GCM-SHA256", SSL_kEECDH|SSL_aECDSA|SSL_AES128GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 128, 128},
#endif
#ifdef ENABLE_SHA384
    {"ecdhe_ecdsa_aes_256_sha_384", TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, "ECDHE-ECDSA-AES256-SHA384", SSL_kEECDH|SSL_aECDSA|SSL_AES256|SSL_SHA384, TLSV1_2, SSL_HIGH, 256, 256},
    {"ecdhe_rsa_aes_256_sha_384", TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, "ECDHE-RSA-AES256-SHA384", SSL_kEECDH|SSL_aRSA|SSL_AES256|SSL_SHA384, TLSV1_2, SSL_HIGH, 256, 256},
    {"ecdhe_ecdsa_aes_256_gcm_sha_384", TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "ECDHE-ECDSA-AES256-GCM-SHA384", SSL_kEECDH|SSL_aECDSA|SSL_AES256GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 256, 256},
    {"ecdhe_rsa_aes_256_gcm_sha_384", TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "ECDHE-RSA-AES256-GCM-SHA384", SSL_kEECDH|SSL_aRSA|SSL_AES256GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 256, 256},
#endif
#ifdef ENABLE_GCM
    {"ecdhe_rsa_aes_128_gcm_sha_256", TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "ECDHE-RSA-AES128-GCM-SHA256", SSL_kEECDH|SSL_aRSA|SSL_AES128GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 128, 128},
#endif
    /* TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 is not implemented */
    /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 is not implemented */
    /* TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 is not implemented */
    /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 is not implemented */
#endif
};

#define CIPHERNUM sizeof(ciphers_def) / sizeof(cipher_properties)
int ciphernum = CIPHERNUM;

/* Some ciphers are optionally enabled in OpenSSL. For safety sake assume
 * they are not available.
 */
static int skip_ciphers = 4;
static int ciphers_not_in_openssl[] = {
    SSL_RSA_FIPS_WITH_DES_CBC_SHA,
    SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
};

static int parse_nss_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum]);
static int parse_openssl_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum]);

int countciphers(PRBool cipher_state[ciphernum], int version) {
    int ciphercount = 0;
    int i = ciphernum;

    for (i = 0; i < ciphernum; i++)
    {
        if ((cipher_state[i] == PR_TRUE) &&
            (ciphers_def[i].version & version)) {
            ciphercount++;
        }
    }

    return ciphercount;
}


int nss_parse_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum])
{
    int rv = 0;

    /* If the string has a colon we use the OpenSSL style. If it has a
     * comma then NSS. If it has neither we try both. */
    if (strchr(ciphers, ':')) {
        rv = parse_openssl_ciphers(s, ciphers, cipher_list);
    } else if (strchr(ciphers, ',')) {
        rv = parse_nss_ciphers(s, ciphers, cipher_list);
    } else {
        rv = parse_openssl_ciphers(s, ciphers, cipher_list);
        if (rv == 0 && 0 == countciphers(cipher_list, SSLV3|TLSV1|TLSV1_2)) {
            rv = parse_nss_ciphers(s, ciphers, cipher_list);
        }
    }
    if (0 == countciphers(cipher_list, SSLV3|TLSV1|TLSV1_2)) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "no cipher match");
    }

    return rv;
}


/* Given a set of ciphers perform a given action on the indexed value.
 *
 * This is needed because the + action doesn't do anything in the NSS
 * context. In OpenSSL it will re-order the cipher list.
 */
static void set_cipher_value(PRBool cipher_list[ciphernum], int index, int action)
{
    int i;

    for (i = 0; i < skip_ciphers; i++) {
        if (ciphers_def[index].num == ciphers_not_in_openssl[i]) {
            cipher_list[index] = -1;
            return;
        }
    }

    if (cipher_list[index] != -1) /* cipher is disabled */
        cipher_list[index] = action;
}


static int parse_openssl_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum])
{
    char * cipher;
    int i, action;
    PRBool merge = PR_FALSE;
    PRBool found = PR_FALSE;
    PRBool first = PR_TRUE;

    cipher = ciphers;
    while (ciphers && (strlen(ciphers)))
    {
        while ((*cipher) && (isspace(*cipher)))
            ++cipher;

        action = 1; /* default to enable */
        switch(*cipher)
        {
            case '+': /* Add something */
                /* Cipher ordering is not supported in NSS */
                return 0;
                break;
            case '-': /* Subtract something */
                action = 0;
                cipher++;
                break;
            case '!':  /* Disable something */
                action = -1;
                cipher++;
                break;
            default:
               /* do nothing */
                break;
        }

        if ((ciphers = strchr(cipher, ':'))) {
            *ciphers++ = '\0';
            merge = PR_FALSE;
            found = PR_FALSE;
        }

        if (!strcmp(cipher, "ALL")) {
            found = PR_TRUE;
            for (i=0; i<ciphernum; i++) {
                if (!(ciphers_def[i].attr & SSL_eNULL))
                    set_cipher_value(cipher_list, i, action);
            }
        } else if (!strcmp(cipher, "COMPLEMENTOFALL")) {
            found = PR_TRUE;
            for (i=0; i<ciphernum; i++) {
                if ((ciphers_def[i].attr & SSL_eNULL))
                    set_cipher_value(cipher_list, i, action);
            }
        } else if (!strcmp(cipher, "DEFAULT")) {
            /* In OpenSSL the default cipher list is
             *    ALL:!aNULL:!eNULL:!SSLv2
             * So we need to disable all the NULL ciphers too.
             */
            int mask = SSL_aNULL | SSL_eNULL;
            found = PR_TRUE;
            for (i=0; i < ciphernum; i++) {
                if (cipher_list[i] != -1)
                    SSL_CipherPrefGetDefault(ciphers_def[i].num,
                                             &cipher_list[i]);
                if (PR_TRUE == first) {
                    if (ciphers_def[i].attr & mask) {
                        set_cipher_value(cipher_list, i, -1);
                    }
                }
            }
        } else if (!strcmp(cipher, "COMPLEMENTOFDEFAULT")) {
            found = PR_TRUE;
            /* no-op. In OpenSSL this is the ADH ciphers */
        } else if (!strcmp(cipher, "@STRENGTH")) {
            /* No cipher ordering in NSS */
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         "Cipher ordering is not supported in NSS");
            return -1;
        } else {
            int amask = 0;
            int amaskaction = 0;
            int mask = 0;
            int strength = 0;
            int protocol = 0;
            char *c;
            int i;
            PRBool candidate_list[ciphernum];
            PRBool temp_list[ciphernum];

            for (i = 0; i < ciphernum; i++) {
                candidate_list[i] = 1;
            }

            c = cipher;
            while (c && (strlen(c))) {
                amask = 0;
                amaskaction = 0;
                mask = 0;
                strength = 0;
                protocol = 0;
                for (i = 0; i < ciphernum; i++) {
                    temp_list[i] = 0;
                }

                if ((c = strchr(cipher, '+'))) {
                    *c++ = '\0';
                }

                if (!strcmp(cipher, "RSA")) {
                    mask |= SSL_RSA;
                } else if (!strcmp(cipher, "kRSA")) {
                    mask |= SSL_kRSA;
                } else if (!strcmp(cipher, "aRSA")) {
                    mask |= SSL_aRSA;
                } else if (!strcmp(cipher, "EDH")) {
                    /* Normally this is kEDH:-ADH but since we don't
                     * support ADH this is sufficient.
                     */
                    mask |= SSL_kEDH;
                } else if (!strcmp(cipher, "DH")) {
                    /* non-ephemeral DH. The ciphers are defined
                     * but not implemented in OpenSSL so manage
                     * this here.
                     */
                    mask |= SSL_kEDH;
#if 0
                } else if (!strcmp(cipher, "ADH")) {
                    mask |= SSL_ADH;
#endif
                } else if (!strcmp(cipher, "ECDH")) {
                    mask |= SSL_ECDH;
                } else if (!strcmp(cipher, "EECDH")) {
                    mask |= SSL_kEECDH;
                    amask = SSL_aNULL;
                    amaskaction = 1; /* filter anonymous out */
                } else if (!strcmp(cipher, "AECDH")) {
                    mask |= SSL_kEECDH;
                    amask = SSL_aNULL; /* require anonymous */
                    amaskaction = 0; /* keep these */
                } else if (!strcmp(cipher, "kECDH")) {
                    mask |= SSL_kECDHe | SSL_kECDHr;
                } else if (!strcmp(cipher, "kECDHe")) {
                    mask |= SSL_kECDHe;
                } else if (!strcmp(cipher, "kECDHr")) {
                    mask |= SSL_kECDHr;
                } else if (!strcmp(cipher, "kEECDH")) {
                    mask |= SSL_kEECDH;
                } else if (!strcmp(cipher, "aECDH")) {
                    mask |= SSL_aECDH;
                } else if (!strcmp(cipher, "ECDSA")) {
                    mask |= SSL_aECDSA;
                } else if (!strcmp(cipher, "aECDSA")) {
                    mask |= SSL_aECDSA;
                } else if ((!strcmp(cipher, "NULL")) || (!strcmp(cipher, "eNULL"))) {
                    mask |= SSL_eNULL;
                } else if (!strcmp(cipher, "aNULL")) {
                    mask |= SSL_aNULL;
                } else if (!strcmp(cipher, "AES")) {
                    mask |= SSL_AES;
                } else if (!strcmp(cipher, "AESGCM")) {
                    mask |= SSL_AES128GCM|SSL_AES256GCM;
                } else if (!strcmp(cipher, "AES128")) {
                    mask |= SSL_AES128|SSL_AES128GCM;
                } else if (!strcmp(cipher, "AES256")) {
                    mask |= SSL_AES256|SSL_AES256GCM;
                } else if (!strcmp(cipher, "CAMELLIA")) {
                    mask |= SSL_CAMELLIA128|SSL_CAMELLIA256;
                } else if (!strcmp(cipher, "CAMELLIA128")) {
                    mask |= SSL_CAMELLIA128;
                } else if (!strcmp(cipher, "CAMELLIA256")) {
                    mask |= SSL_CAMELLIA256;
                } else if (!strcmp(cipher, "3DES")) {
                    mask |= SSL_3DES;
                } else if (!strcmp(cipher, "DES")) {
                    mask |= SSL_DES;
                } else if (!strcmp(cipher, "RC4")) {
                    mask |= SSL_RC4;
                } else if (!strcmp(cipher, "RC2")) {
                    mask |= SSL_RC2;
                } else if (!strcmp(cipher, "MD5")) {
                    mask |= SSL_MD5;
                } else if ((!strcmp(cipher, "SHA")) || (!strcmp(cipher, "SHA1"))) {
                    mask |= SSL_SHA1;
                } else if (!strcmp(cipher, "SHA256")) {
                    mask |= SSL_SHA256;
                } else if (!strcmp(cipher, "SHA384")) {
                    mask |= SSL_SHA384;
                } else if (!strcmp(cipher, "SSLv2")) {
                    /* no-op */
                } else if (!strcmp(cipher, "SSLv3")) {
                    protocol |= SSLV3;
                } else if (!strcmp(cipher, "TLSv1")) {
                    protocol |= TLSV1;
                } else if (!strcmp(cipher, "TLSv1.2")) {
                    protocol |= TLSV1_2;
                } else if (!strcmp(cipher, "HIGH")) {
                    strength |= SSL_HIGH;
                } else if (!strcmp(cipher, "MEDIUM")) {
                    strength |= SSL_MEDIUM;
                } else if (!strcmp(cipher, "LOW")) {
                    strength |= SSL_LOW;
                } else if ((!strcmp(cipher, "EXPORT")) || (!strcmp(cipher, "EXP"))) {
                    strength |= SSL_EXPORT40|SSL_EXPORT56;
                } else if (!strcmp(cipher, "EXPORT40")) {
                    strength |= SSL_EXPORT40;
                } else if (!strcmp(cipher, "EXPORT56")) {
                    strength |= SSL_EXPORT56;
                }

                if (c)
                    cipher = c;

                /* If we have a mask, apply it. If not then perhaps they
                 * provided a specific cipher to enable.
                 */
                if (mask || strength || protocol) {
                    merge = PR_TRUE;
                    found = PR_TRUE;
                    for (i=0; i<ciphernum; i++) {
                        if (((ciphers_def[i].attr & mask) ||
                         (ciphers_def[i].strength & strength) ||
                         (ciphers_def[i].version & protocol)) &&
                         (cipher_list[i] != -1)) {
                            if (amask != 0) {
                                PRBool match = PR_FALSE;
                                if (ciphers_def[i].attr & amask) {
                                    match = PR_TRUE;
                                }
                                if (amaskaction && match)
                                    continue;
                                if (!amaskaction && !match)
                                    continue;
                            }
#if 0
                            /* Enable the NULL ciphers only if explicity
                             * requested */
                            if (ciphers_def[i].attr & SSL_eNULL) {
                                if (mask & SSL_eNULL)
                                    temp_list[i] = 1;
                            } else
#endif
                                temp_list[i] = 1;
                            }
                    }
                    /* Merge the temp list into the candidate list */
                    for (i=0; i<ciphernum; i++) {
                        if (!(candidate_list[i] & temp_list[i])) {
                            candidate_list[i] = 0;
                        }
                    }
                } else if (!strcmp(cipher, "FIPS")) {
                        SSLCipherSuiteInfo suite;
                    for (i=0; i<ciphernum;i++) {
                        if (SSL_GetCipherSuiteInfo(ciphers_def[i].num,
                            &suite, sizeof suite) == SECSuccess) {
                            if (suite.isFIPS)
                                set_cipher_value(cipher_list, i, action);
                        }
                    }
                } else {
                    for (i=0; i<ciphernum; i++) {
                        if (!strcmp(ciphers_def[i].openssl_name, cipher))
                            set_cipher_value(cipher_list, i, action);
                    }
                }
            } /* while */
            if (PR_TRUE == merge) {
                first = PR_FALSE;
                /* Merge the candidate list into the cipher list */
                for (i=0; i<ciphernum; i++) {
                    if (candidate_list[i])
                        set_cipher_value(cipher_list, i, action);
                }
                merge = PR_FALSE;
                found = PR_FALSE;
            }
        }

        if (ciphers)
            cipher = ciphers;

    }
    if (found && 0 == countciphers(cipher_list, SSLV3|TLSV1|TLSV1_2))
        return 1; /* no matching ciphers */
    return 0;
}


static int parse_nss_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum])
{
    char * cipher;
    PRBool found;
    int i, active;

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
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
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
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         "Unknown cipher %s\n", cipher);
        }

        if (ciphers) {
            cipher = ciphers;
        }
    }

    return 0;
}
