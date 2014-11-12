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
cipher_properties ciphers_def[ciphernum] =
{
    {"rsa_null_md5", TLS_RSA_WITH_NULL_MD5, "NULL-MD5", SSL_kRSA|SSL_aRSA|SSL_eNULL|SSL_MD5, SSLV3, SSL_STRONG_NONE, 0, 0},
    {"rsa_null_sha", TLS_RSA_WITH_NULL_SHA, "NULL-SHA", SSL_kRSA|SSL_aRSA|SSL_eNULL|SSL_SHA1, SSLV3, SSL_STRONG_NONE, 0, 0},
    {"rsa_rc4_40_md5", TLS_RSA_EXPORT_WITH_RC4_40_MD5, "EXP-RC4-MD5", SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5, SSLV3, SSL_EXPORT40, 40, 128},
    {"rsa_rc4_128_md5", TLS_RSA_WITH_RC4_128_MD5, "RC4-MD5", SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5, SSLV3, SSL_MEDIUM, 128, 128},
    {"rsa_rc4_128_sha", TLS_RSA_WITH_RC4_128_SHA, "RC4-SHA", SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_SHA1, SSLV3, SSL_MEDIUM, 128, 128},
    {"rsa_rc2_40_md5", TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, "EXP-RC2-CBC-MD5", SSL_kRSA|SSL_aRSA|SSL_RC2|SSL_MD5, SSLV3, SSL_EXPORT40, 40, 128},
    {"rsa_des_sha", TLS_RSA_WITH_DES_CBC_SHA, "DES-CBC-SHA", SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1, SSLV3, SSL_LOW, 56, 56},
    {"rsa_3des_sha", TLS_RSA_WITH_3DES_EDE_CBC_SHA, "DES-CBC3-SHA", SSL_kRSA|SSL_aRSA|SSL_3DES|SSL_SHA1, SSLV3, SSL_HIGH, 112, 168},
    {"rsa_aes_128_sha", TLS_RSA_WITH_AES_128_CBC_SHA, "AES128-SHA", SSL_kRSA|SSL_aRSA|SSL_AES128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128},
    {"rsa_aes_256_sha", TLS_RSA_WITH_AES_256_CBC_SHA, "AES256-SHA256", SSL_kRSA|SSL_aRSA|SSL_AES256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256},
    {"null_sha_256", TLS_RSA_WITH_NULL_SHA256, "NULL-SHA256", SSL_kRSA|SSL_aRSA|SSL_eNULL|SSL_SHA256, TLSV1_2, SSL_STRONG_NONE, 0, 0},
    {"aes_128_sha_256", TLS_RSA_WITH_AES_128_CBC_SHA256, "AES128-SHA256", SSL_kRSA|SSL_aRSA|SSL_AES128|SSL_SHA256, TLSV1_2, SSL_HIGH, 128, 128},
    {"aes_256_sha_256", TLS_RSA_WITH_AES_256_CBC_SHA256, "AES256-SHA256", SSL_kRSA|SSL_aRSA|SSL_AES256|SSL_SHA256, TLSV1_2, SSL_HIGH, 256, 256},
    {"camelia_128_sha", TLS_RSA_WITH_CAMELLIA_128_CBC_SHA, "CAMELLIA128-SHA", SSL_kRSA|SSL_aRSA|SSL_CAMELLIA128|SSL_SHA1, TLSV1, SSL_HIGH, 128, 128},
    {"rsa_des_56_sha", TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA, "EXP1024-DES-CBC-SHA", SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1, TLSV1, SSL_EXPORT56, 56, 56},
    {"rsa_rc4_56_sha", TLS_RSA_EXPORT1024_WITH_RC4_56_SHA, "EXP1024-RC4-SHA", SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_SHA1, TLSV1, SSL_EXPORT56, 56, 128},
    {"camelia_256_sha", TLS_RSA_WITH_CAMELLIA_256_CBC_SHA, "CAMELLIA256-SHA", SSL_kRSA|SSL_aRSA|SSL_CAMELLIA256|SSL_SHA1, TLSV1, SSL_HIGH, 256, 256},
    {"rsa_aes_128_gcm_sha_256", TLS_RSA_WITH_AES_128_GCM_SHA256, "AES128-GCM-SHA256", SSL_kRSA|SSL_aRSA|SSL_AES128GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 128, 128},
    {"fips_3des_sha", SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA, "FIPS-DES-CBC3-SHA", SSL_kRSA|SSL_aRSA|SSL_3DES|SSL_SHA1, SSLV3, SSL_HIGH, 112, 168},
    {"fips_des_sha", SSL_RSA_FIPS_WITH_DES_CBC_SHA, "FIPS-DES-CBC-SHA", SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1, SSLV3, SSL_LOW, 56, 56},
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
    {"ecdhe_ecdsa_aes_128_gcm_sha_256", TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "ECDHE-ECDSA-AES128-GCM-SHA256", SSL_kEECDH|SSL_aECDSA|SSL_AES128GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 128, 128},
    {"ecdhe_rsa_aes_128_gcm_sha_256", TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "ECDHE-RSA-AES128-GCM-SHA256", SSL_kEECDH|SSL_aRSA|SSL_AES128GCM|SSL_AEAD, TLSV1_2, SSL_HIGH, 128, 128},
#endif
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
        if (0 == countciphers(cipher_list, SSLV3|TLSV1|TLSV1_2)) {
            rv = parse_nss_ciphers(s, ciphers, cipher_list);
        }
    }

    return rv;
}


static int parse_openssl_ciphers(server_rec *s, char *ciphers, PRBool cipher_list[ciphernum])
{
    char * cipher;
    int i, action;

    cipher = ciphers;
    while (ciphers && (strlen(ciphers)))
    {
        while ((*cipher) && (isspace(*cipher)))
            ++cipher;

        action = 1;
        switch(*cipher)
        {
            case '+': /* Add something */
                action = 1;
                cipher++;
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
        }

        if (!strcmp(cipher, "ALL")) {
            for (i=0; i<ciphernum; i++) {
                if (!(ciphers_def[i].attr & SSL_eNULL))
                    if (cipher_list[i] != -1)
                        cipher_list[i] = action;
            }
        } else if (!strcmp(cipher, "COMPLEMENTOFALL")) {
            for (i=0; i<ciphernum; i++) {
                if ((ciphers_def[i].attr & SSL_eNULL))
                    if (cipher_list[i] != -1)
                        cipher_list[i] = action;
            }
        } else if (!strcmp(cipher, "DEFAULT")) {
            for (i=0; i < ciphernum; i++) {
                if (cipher_list[i] != -1)
                    SSL_CipherPrefGetDefault(ciphers_def[i].num,
                                             &cipher_list[i]);
            }
        } else {
            int mask = 0;
            int strength = 0;
            int protocol = 0;
            char *c;

            c = cipher;
            while (c && (strlen(c))) {

                if ((c = strchr(cipher, '+'))) {
                    *c++ = '\0';
                }

                if (!strcmp(cipher, "RSA")) {
                    mask |= SSL_RSA;
                } else if (!strcmp(cipher, "EDH")) {
                    mask |= SSL_EDH;
                } else if ((!strcmp(cipher, "NULL")) || (!strcmp(cipher, "eNULL"))) {
                    mask |= SSL_eNULL;
                } else if (!strcmp(cipher, "AES")) {
                    mask |= SSL_AES;
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
                } else if (!strcmp(cipher, "SSLv2")) {
                    /* no-op */
                } else if (!strcmp(cipher, "SSLv3")) {
                    protocol |= SSLV3;
                } else if (!strcmp(cipher, "TLSv1")) {
                    protocol |= TLSV1;
                } else if (!strcmp(cipher, "TLSv12")) {
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

            } /* while */

            /* If we have a mask, apply it. If not then perhaps they provided
             * a specific cipher to enable.
             */
            if (mask || strength || protocol)
                for (i=0; i<ciphernum; i++) {
                    if (((ciphers_def[i].attr & mask) ||
                     (ciphers_def[i].strength & strength) ||
                     (ciphers_def[i].version & protocol)) &&
                     (cipher_list[i] != -1)) {
                        /* Enable the NULL ciphers only if explicity
                         * requested */
                        if (ciphers_def[i].attr & SSL_eNULL) {
                            if (mask & SSL_eNULL)
                                cipher_list[i] = action;
                        } else
                            cipher_list[i] = action;
                    }
                }
            else {
                for (i=0; i<ciphernum; i++) {
                    if (!strcmp(ciphers_def[i].openssl_name, cipher) &&
                        cipher_list[i] != -1)
                        cipher_list[i] = action;
                }
            }
        }

        if (ciphers)
            cipher = ciphers;

    }
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
