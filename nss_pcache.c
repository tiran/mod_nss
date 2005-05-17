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
#include <string.h>
#include <nss.h>
#include <nspr.h>
#include <secitem.h>
#include <prtypes.h>
#include <seccomon.h>
#include <pk11func.h>
#include "nss_pcache.h"

static char * getstr(const char * cmd, int el);
char* INTERNAL_TOKEN_NAME = "internal                         ";

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
    PK11SlotInfo *slot;

    const mech_item *mech;

    PK11SymKey *key;
    SECItem *params;

    int length;
    unsigned char *crypt;
};

/*
 * Node - for maintaining link list of tokens with cached PINs
 */
typedef struct Node Node;
static void freeList(Node *list);

struct Node
{
  Node *next;
  char *tokenName;
  Pk11PinStore *store;
};

/* global variables */
Node *pinList = NULL;

/*
 * CreatePk11PinStore
 */
int
CreatePk11PinStore(Pk11PinStore **out, const char *tokenName, const char *pin)
{
    int err = PIN_SUCCESS;
    Pk11PinStore *store;

    do {

        store = (Pk11PinStore*)malloc(sizeof(Pk11PinStore));
        if (store == 0) { err = PIN_NOMEMORY; break; }

        /* Low-level init */
        store->key = 0;
        store->params = 0;
        store->crypt = 0;

        /* Use the tokenName to find a PKCS11 slot */
        store->slot = PK11_FindSlotByName((char *)tokenName);
        if (store->slot == 0) { err = PIN_NOSUCHTOKEN; break; }

        /* Check the password/PIN.  This allows access to the token */
        {
            SECStatus rv = PK11_CheckUserPassword(store->slot, (char *)pin);

            if (rv == SECSuccess)
                ;
            else if (rv == SECWouldBlock)
            {
                /* NSS returns a blocking error when the pin is wrong */
                err = PIN_INCORRECTPW;
                break;
            }
            else
            {
                err = PIN_SYSTEMERROR;
                break;
            }
        }

        /* Find the mechanism that this token can do */
        {
            const mech_item *tp;

            store->mech = 0;
            for(tp = table;tp < &table[MECH_TABLE_SIZE];tp++)
            {
                if (PK11_DoesMechanism(store->slot, tp->type))
                {
                    store->mech = (mech_item *)tp;
                    break;
                }
            }
            /* Default to a mechanism (probably on the internal token */
            if (store->mech == 0) {
                store->mech = &dflt_mech;
            }
        }

        /* Generate a key and parameters to do the encryption */
        store->key = PK11_KeyGen(store->slot, store->mech->type,
                       0, 0, 0);
        if (store->key == 0)
        {
            /* PR_SetError(xxx); */
            err = PIN_SYSTEMERROR;
            break;
        }

        store->params = PK11_GenerateNewParam(store->mech->type, store->key);
        if (store->params == 0)
        {
            err = PIN_SYSTEMERROR;
            break;
        }

        /* Compute the size of the encrypted data including necessary padding */
        {
            int blocksize = PK11_GetBlockSize(store->mech->type, 0);

            store->length = strlen(pin)+1;

            /* Compute padded size - 0 means stream cipher */
            if (blocksize != 0)
            {
                store->length += blocksize - (store->length % blocksize);
            }

            store->crypt = (unsigned char *)malloc(store->length);
            if (!store->crypt) { err = PIN_NOMEMORY; break; }
        }

        /* Encrypt */
        {
            unsigned char *plain;
            PK11Context *ctx;
            SECStatus rv;
            int outLen;

            plain = (unsigned char *)malloc(store->length);
            if (!plain) { err = PIN_NOMEMORY; break; }

            /* Pad with 0 bytes */
            memset(plain, 0, store->length);
            strcpy((char *)plain, pin);

            ctx = PK11_CreateContextBySymKey(store->mech->type, CKA_ENCRYPT,
                    store->key, store->params);
            if (!ctx) { err = PIN_SYSTEMERROR; break; }

            do {
                rv = PK11_CipherOp(ctx, store->crypt, &outLen, store->length,
                       plain, store->length);
                if (rv) break;

                rv = PK11_Finalize(ctx);
            } while(0);

            PK11_DestroyContext(ctx, PR_TRUE);
            memset(plain, 0, store->length);
            free(plain);

            if (rv) err = PIN_SYSTEMERROR;
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

    if (store->key) {
        PK11_FreeSymKey(store->key);
    }

    if (store->crypt) {
        memset(store->crypt, 0, store->length);
        free(store->crypt);
    }

    free(store);
}

int
Pk11StoreGetPin(char **out, Pk11PinStore *store)
{
    int err = PIN_SUCCESS;
    unsigned char *plain;
    SECStatus rv = SECSuccess;
    PK11Context *ctx = 0;
    int outLen;

    do {
        plain = (unsigned char *)malloc(store->length);
        if (!plain) { err = PIN_NOMEMORY; break; }

        ctx = PK11_CreateContextBySymKey(store->mech->type, CKA_DECRYPT,
                  store->key, store->params);
        if (!ctx) { err = PIN_SYSTEMERROR; break; }

        rv = PK11_CipherOp(ctx, plain, &outLen, store->length,
               store->crypt, store->length);
        if (rv) break;

        rv = PK11_Finalize(ctx);
        if (rv) break;
    } while(0);

    if (ctx) PK11_DestroyContext(ctx, PR_TRUE);

    if (rv)
    {
        err = PIN_SYSTEMERROR;
        memset(plain, 0, store->length);
        free(plain);
        plain = 0;
    }

    *out = (char *)plain;
    return err;
}

int main(int argc, char ** argv)
{
    SECStatus rv;
    PRFileDesc *in;
    PRFileDesc *out;
    PRPollDesc pd;
    PRIntervalTime timeout = PR_INTERVAL_NO_TIMEOUT;
    char buf[1024];
    PRInt32 nBytes;
    char * command;
    char * tokenName;
    char * tokenpw;

    /* Initialize NSPR */
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 256);
 
    /* Set the PKCS #11 strings for the internal token. */
    PK11_ConfigurePKCS11(NULL,NULL,NULL, INTERNAL_TOKEN_NAME, NULL, NULL,NULL,NULL,8,1);
 
    /* Initialize NSS and open the certificate database read-only. */
    rv = NSS_Initialize("/home/rcrit/redhat/apache//conf/nss/", NULL, NULL, "secmod.db", NSS_INIT_READONLY);

    in = PR_GetSpecialFD(PR_StandardInput);
    out = PR_GetSpecialFD(PR_StandardOutput);
    if (in == NULL || out == NULL) {
        fprintf(stderr, "PR_GetInheritedFD failed\n"); 
        exit(1);
    }

    pd.fd = in;
    pd.in_flags = PR_POLL_READ | PR_POLL_EXCEPT;
    while (1) {
        rv = PR_Poll(&pd, 1, timeout);
        if (rv == -1) { /* PR_Poll failed */
            break;
        }
        if (pd.out_flags & (PR_POLL_HUP | PR_POLL_ERR | PR_POLL_NVAL | PR_POLL_EXCEPT)) {
            break;
        }
        if (pd.out_flags & PR_POLL_READ) {
            memset(buf, 0, sizeof(buf));
            nBytes = PR_Read(in, buf, sizeof(buf));
            if (nBytes == -1 || nBytes == 0) {
                break;
            }
            command = getstr(buf, 0);
            tokenName = getstr(buf, 1);
            tokenpw = getstr(buf, 2);

            if (command && !strcmp(command, "QUIT")) {
                break;
            } else if (command && !strcmp(command, "STOR")) {
                PRInt32 err = PIN_SUCCESS;
                Node *node = NULL;

                if (tokenName && tokenpw) {
                    node = (Node*)malloc(sizeof (Node));
                    if (!node) { err = PIN_NOMEMORY; }

                    node->tokenName = strdup(tokenName);
                    node->store = 0; 
                    node->next = 0; 

                    if (err == PIN_SUCCESS)
                        err = CreatePk11PinStore(&node->store, tokenName, tokenpw);
                    memset(tokenpw, 0, strlen(tokenpw));
                } else
                    err = PIN_SYSTEMERROR;

                sprintf(buf, "%d", err);
                PR_Write(out, buf, 1);

                if (err == PIN_SUCCESS) {
                    if (pinList)
                        node->next = pinList;
                    pinList = node;
                }

                /* Now clean things up */
                if (command) free(command);
                if (tokenName) free(tokenName);
                if (tokenpw) free(tokenpw);
            } else if (command && !strcmp(command, "RETR")) {
                Node *node;
                char *pin = 0;
                PRBool found = PR_FALSE;

                for (node = pinList; node != NULL; node = node->next) {
                    if (!strcmp(node->tokenName, tokenName)) {
                        if (Pk11StoreGetPin(&pin, node->store) == SECSuccess) {
                            PR_Write(out, pin, strlen(pin));
                            memset(pin, 0, strlen(pin));
                            free(pin);
                            found = PR_TRUE;
                            break;
                        }
                    }
                }

                if (found != PR_TRUE)
                    PR_Write(out, "", 1);

                free(command);
                free(tokenName);
            } else {
              ; /* ack, unknown command */
            }
        }
    }
    freeList(pinList);
    PR_Close(in);
    return 0;
}

/* 
 * Given a \t-deliminated string, pick out the el-th element
 */
static
char * getstr(const char * cmd, int el) {
    char *work, *s, *t, *r;
    char *peek;
    int i = 0;

    work = strdup(cmd);
    s = t = work;

    peek = s;
    if (peek)
        peek++;
    while (*s) {
        if (*s == '\t' || *peek == '\0') {
            if (i == el) {
                if (*peek != '\0')
                    *s = '\0';
                r = strdup(t);
                free(work);
                return r;
            } else { /* not the element we want */
                i++;
                s++;
                peek++;
                t = s;
            }
        }
        s++;
        peek++;
    }

    free(work);
    return NULL;
}

/*
 * Node implementation
 */

static void freeList(Node *list)
{
    Node *n1;
    Node *n2;

    n1 = list;

    while (n1) {

        n2 = n1;
        if (n2->store) DestroyPk11PinStore(n2->store);
        if (n2->tokenName) free(n2->tokenName);
        n1 = n2->next;
        free(n2);

    }
}
