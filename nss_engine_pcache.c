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

/*
 * Mechanisms for doing the PIN encryption.  Each of these lists
 * an encryption mechanism, with setup, encode and decode routines that
 * use that mechanism.  The PK11PinStore looks for a mechanism
 * that the token supports, and then uses it.  If none is found,
 * it will fail.
 */
typedef struct mech_item mech_item;

struct mech_item
{
  CK_MECHANISM_TYPE type;
  const char *mechName;
};

/*
 * The table listing all mechanism to try
 */
#define MECH_TABLE_SIZE 4
static const mech_item table[MECH_TABLE_SIZE] = {
  { CKM_SKIPJACK_CBC64, "Skipjack CBC-64 encryption" },
  { CKM_DES3_CBC,       "Triple-DES CBC encryption" },
  { CKM_CAST128_CBC,    "CAST-128 CBC encryption" },
  { CKM_DES_CBC,        "DES CBC encryption" }
};

static mech_item dflt_mech = { CKM_DES3_CBC, "Triple-DES CBC (default)" };

/*
 * Implementation
 */
struct Pk11PinStore
{
    char *tokenName;

    mech_item *mech;

    SECItem *key;
    SECItem *params;

    int length;
    unsigned char *crypt;
};

/*
 * CreatePk11PinStore
 */
SECStatus
CreatePk11PinStore(apr_pool_t *pool, Pk11PinStore **out, const char *tokenName, const char *pin)
{
    SECStatus err;
    Pk11PinStore *store;
    PK11SymKey *tmpkey;
    SECItem *tmpparams;
    PK11SlotInfo *slot;

    do {
        err = SECSuccess;

        store = (Pk11PinStore*)apr_pcalloc(pool, sizeof(Pk11PinStore));
        if (store == 0) { err = SECFailure; break; }

        /* Low-level init */
        store->tokenName = 0;
        store->key = 0;
        store->params = 0;
        store->crypt = 0;

        store->mech = (mech_item *)apr_pcalloc(pool, sizeof(mech_item));

        /* Use the tokenName to find a PKCS11 slot */
        slot = PK11_FindSlotByName((char *)tokenName);
        if (slot == 0) { err = SECFailure; break; }

        /* Check the password/PIN.  This allows access to the token */
        {
            SECStatus rv = PK11_CheckUserPassword(slot, (char *)pin);

            if (rv == SECSuccess)
                ;
            else if (rv == SECWouldBlock)
            {
                err = SECFailure;
                break;
            }
            else
            {
                err = SECFailure;
                break;
            }
        }
        store->tokenName = apr_pstrdup(pool, tokenName);

        /* Find the mechanism that this token can do */
        {
            const mech_item *tp;

            for(tp = table;tp < &table[MECH_TABLE_SIZE];tp++)
            {
                if (PK11_DoesMechanism(slot, tp->type))
                {
//                    store->mech = tp;
                    store->mech->type = tp->type;
                    store->mech->mechName = apr_pstrdup(pool, tp->mechName);
                    break;
                }
            }
            /* Default to a mechanism (probably on the internal token */
            if (store->mech == 0) {
//                store->mech = &dflt_mech;
                    store->mech->type = dflt_mech.type;
                    store->mech->mechName = (char *)apr_pstrdup(pool, dflt_mech.mechName);
            }
        }

        /* Generate a key and parameters to do the encryption */
        tmpkey = PK11_KeyGen(slot, store->mech->type,
                       0, 0, 0);
        if (tmpkey == 0)
        {
            /* PR_SetError(xxx); */
            err = SECFailure;
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "key failed %d", PR_GetError());
            break;
        }
        {
        SECItem *keydata = PK11_GetKeyData(tmpkey);

        store->key = (SECItem *)apr_pcalloc(pool, sizeof(SECItem));
        store->key->type = keydata->type;
        store->key->len = keydata->len;
        store->key->data = apr_pcalloc(pool, keydata->len);
        memcpy(store->key->data, keydata->data, keydata->len);
        if (SECITEM_CompareItem(store->key, keydata) != SECEqual)
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "key copy failed");
        }

        tmpparams = PK11_GenerateNewParam(store->mech->type, tmpkey);
        if (tmpparams == 0)
        {
            err = SECFailure;
            break;
        }
        store->params = (SECItem *)apr_pcalloc(pool, sizeof(SECItem));
        store->params->len = tmpparams->len;
        store->params->data = apr_pcalloc(pool, tmpparams->len);
        store->params->type = tmpparams->type;
        memcpy(store->params->data, tmpparams->data, tmpparams->len);
        if (SECITEM_CompareItem(store->params, tmpparams) != SECEqual)
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "params copy failed");

        /* Compute the size of the encrypted data including necessary padding */
        {
            int blocksize = PK11_GetBlockSize(store->mech->type, 0);

            store->length = strlen(pin)+1;

            /* Compute padded size - 0 means stream cipher */
            if (blocksize != 0)
            {
                store->length += blocksize - (store->length % blocksize);
            }

            store->crypt = (unsigned char *)apr_pcalloc(pool, store->length);
            if (!store->crypt) { err = SECFailure; break; }
        }

        /* Encrypt */
        {
            unsigned char *plain;
            PK11Context *ctx;
            SECStatus rv;
            int outLen;

            plain = (unsigned char *)malloc(store->length);
            if (!plain) { err = SECFailure; break; }

            /* Pad with 0 bytes */
            memset(plain, 0, store->length);
            strcpy((char *)plain, pin);

            ctx = PK11_CreateContextBySymKey(store->mech->type, CKA_ENCRYPT,
                    tmpkey, store->params);
            if (!ctx) { err = SECFailure; break; }

            do {
                rv = PK11_CipherOp(ctx, store->crypt, &outLen, store->length,
                       plain, store->length);
                if (rv) break;

                rv = PK11_Finalize(ctx);
            } while(0);

            PK11_DestroyContext(ctx, PR_TRUE);
            memset(plain, 0, store->length);
            free(plain);

            if (rv) err = SECFailure;
        }
    } while(0);

    if (err)
    {
        DestroyPk11PinStore(store);
        store = 0;
    }

    *out = store;
    return err;
}

/*
 * DestroyPk11PinStore
 */
void DestroyPk11PinStore(Pk11PinStore *store)
{
    if (store == 0) return;

    if (store->params) {
        SECITEM_ZfreeItem(store->params, PR_TRUE);
    }

    if (store->crypt) {
        memset(store->crypt, 0, store->length);
        free(store->crypt);
    }

    free(store);
}

SECStatus Pk11StoreGetPin(char **out, Pk11PinStore *store)
{
    SECStatus err = SECSuccess;
    unsigned char *plain;
    SECStatus rv;
    PK11Context *ctx = 0;
    int outLen;
    PK11SlotInfo *slot;
    PK11SymKey * tmpkey;

    do {
        plain = (unsigned char *)malloc(store->length);
        if (!plain) { err = SECFailure;ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "plain is null"); break; }

        slot = PK11_FindSlotByName(store->tokenName);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "slot is %s param len is %d", store->tokenName, store->params->len);
        if (slot == 0) {
             ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "no slot");
             err=SECFailure;break;
        }
        tmpkey = PK11_KeyGen(slot, store->mech->type,
                       store->key, 0, 0);
        ctx = PK11_CreateContextBySymKey(store->mech->type, CKA_DECRYPT,
                  tmpkey, store->params);
        if (!ctx) { err = SECFailure; ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "ctx is null %d", PR_GetError());break; }

        rv = PK11_CipherOp(ctx, plain, &outLen, store->length,
               store->crypt, store->length);
        if (rv) { ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "cipherop failed");break; }

        rv = PK11_Finalize(ctx);
        if (rv) break;
    } while(0);

    if (ctx) PK11_DestroyContext(ctx, PR_TRUE);

    if (rv)
    {
        err = SECFailure;
        memset(plain, 0, store->length);
        free(plain);
        plain = 0;
    }

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "plain is %s", plain);
    *out = (char *)plain;
    return err;
}
