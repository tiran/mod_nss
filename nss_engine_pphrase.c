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
#include <termios.h> /* for echo on/off */
#include "nss_pcache.h"

typedef struct {
    SSLModConfigRec *mc;
    server_rec *s;
    PRInt32 retryCount;
} pphrase_arg_t;

static char * nss_password_prompt(PK11SlotInfo *slot, PRBool retry, void *arg);
static char * nss_no_password(PK11SlotInfo *slot, PRBool retry, void *arg);
static char * nss_get_password(FILE *input, FILE *output, PK11SlotInfo *slot, PRBool (*ok)(unsigned char *), pphrase_arg_t * parg);
static PRBool nss_check_password(unsigned char *cp);
static void echoOff(int fd);
static void echoOn(int fd);

/*
 * Global variables defined in this file.
 */
static char * prompt;

/*
 * Initialize all SSL tokens. This involves authenticating the user
 * against the token password. It is possible that some tokens may
 *  be authenticated and others will not be.
 */

SECStatus nss_Init_Tokens(server_rec *s)
{
    PK11SlotList        *slotList;
    PK11SlotListElement *listEntry;
    SECStatus ret, status = SECSuccess;
    SSLModConfigRec *mc = myModConfig(s);
    pphrase_arg_t * parg;

    parg = (pphrase_arg_t*)malloc(sizeof(*parg));
    parg->mc = mc;
    parg->retryCount = 0;
    parg->s = s;

    PK11_SetPasswordFunc(nss_password_prompt);

    slotList = PK11_GetAllTokens(CKM_INVALID_MECHANISM, PR_FALSE, PR_TRUE, NULL);

    for (listEntry = PK11_GetFirstSafe(slotList);
        listEntry;
        listEntry = listEntry->next)
    {
        PK11SlotInfo *slot = listEntry->slot;

        /* This is needed to work around a bug in NSS while in FIPS mode.
         * The first login will succeed but NSS_Shutdown() isn't cleaning
         * something up causing subsequent logins to be skipped making
         * keys and certs unavailable.
         */
        PK11_Logout(slot);

        if (PK11_NeedLogin(slot) && PK11_NeedUserInit(slot)) {
            if (slot == PK11_GetInternalKeySlot()) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "The server key database has not been initialized.");
            } else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "The token %s has not been initialized.", PK11_GetTokenName(slot));
            }
            PK11_FreeSlot(slot);
            continue;
        }

        if (parg->mc->pphrase_dialog_type == SSL_PPTYPE_DEFER) {
            char * passwd = nss_get_password(stdin, stdout, slot, nss_check_password, parg);
            if (passwd == NULL) {
                PK11_FreeSlot(slot);
                continue;
            }
            free(passwd);
        }

        ret = PK11_Authenticate(slot, PR_TRUE, parg);
        if (SECSuccess != ret) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "Password for slot %s is incorrect.", PK11_GetTokenName(slot));
            PK11_FreeSlot(slot);
            /* We return here rather than breaking because:
               1. All tokens must be logged for the server to work.
               2. We'll get a bogus error message from nss_engine_init, -8053,
                  instead of -8177.
             */
            return SECFailure;
        }
        parg->retryCount = 0; /* reset counter to 0 for the next token */
        PK11_FreeSlot(slot);
    }

    /*
     * reset NSS password callback to blank, so that the server won't prompt
     * again after initialization is done.
     */
    PK11_SetPasswordFunc(nss_no_password);

    free(parg);
    return status;
}

/*
 * Wrapper callback function that prompts the user for the token password
 * up to 3 times.
 */
static char * nss_password_prompt(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    char *passwd = NULL;
    pphrase_arg_t *parg = (pphrase_arg_t *)arg;

    if (arg && retry) {
        parg->retryCount++;
    }
    prompt = PR_smprintf("Please enter password for \"%s\" token:", PK11_GetTokenName(slot));
    if (parg == NULL) {
        /* should not happen */
        passwd = nss_get_password(stdin, stdout, slot, nss_check_password, 0);
    } else {
        if (parg->retryCount > 2) {
            passwd = NULL; /* abort after 2 retries (3 failed attempts) */
        } else {
            passwd = nss_get_password(stdin, stdout, slot, nss_check_password, parg);
        }
    }

    if ((parg && parg->mc && parg->mc->nInitCount == 1) && (passwd != NULL)) {
        char buf[1024];
        apr_status_t rv;
        apr_size_t nBytes = 1024;
        int res = PIN_SUCCESS;

        snprintf(buf, 1024, "STOR\t%s\t%s", PK11_GetTokenName(slot), passwd);
        rv = apr_file_write_full(parg->mc->proc.in, buf, strlen(buf), NULL);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parg->s,
                "Unable to write to pin store for slot: %s APR err: %d",  PK11_GetTokenName(slot), rv);
            nss_die();
        }

        /* Check the result. We don't really care what we got back as long
         * as the communication was successful. If the token password was
         * bad it will get handled later, we don't need to do anything
         * about it here.
         */
        memset(buf, 0, sizeof(buf));
        rv = apr_file_read(parg->mc->proc.out, buf, &nBytes);

        if (rv == APR_SUCCESS)
            res = atoi(buf);
        if (rv != APR_SUCCESS ||
           (res != PIN_SUCCESS && res != PIN_INCORRECTPW)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parg->s,
                "Unable to read from pin store for slot: %s APR err: %d pcache: %d",  PK11_GetTokenName(slot), rv, res);
            nss_die();
        }
    }

    return passwd;
}

/*
 * Enforce basic password sanity rules on the password. We don't do
 * any actual enforcement here but it demonstrates the sorts of things
 * that may be done.
 */
static PRBool nss_check_password(unsigned char *cp)
{
    int len;
    unsigned char *end, ch;

    len = strlen((char *)cp);
    if (len < 8) {
            return PR_TRUE;
    }
    end = cp + len;
    while (cp < end) {
        ch = *cp++;
        if (!((ch >= 'A') && (ch <= 'Z')) &&
            !((ch >= 'a') && (ch <= 'z'))) {
            /* pass phrase has at least one non alphabetic in it */
            return PR_TRUE;
        }
    }
    return PR_TRUE;
}

/*
 * Password callback so the user is not prompted to enter the password
 * after the server starts.
 */
static char * nss_no_password(PK11SlotInfo *slot, PRBool retry, void *arg)
{
   return NULL;
}

/*
 * Password callback to prompt the user for a password. This requires
 * twiddling with the tty. Alternatively, if the file password.conf
 * exists then it may be used to store the token password(s).
 */
static char *nss_get_password(FILE *input, FILE *output,
                              PK11SlotInfo *slot,
                              PRBool (*ok)(unsigned char *),
                              pphrase_arg_t *parg)
{
    char *pwdstr = NULL;
    char *token_name = NULL;
    int tmp;
    FILE *pwd_fileptr;
    char *ptr;
    char line[1024];
    unsigned char phrase[200];
    int infd = fileno(input);
    int isTTY = isatty(infd);

    token_name = PK11_GetTokenName(slot);

    if (parg->mc->pphrase_dialog_type == SSL_PPTYPE_FILE ||
        parg->mc->pphrase_dialog_type == SSL_PPTYPE_DEFER) {
        /* Try to get the passwords from the password file if it exists.
         * THIS IS UNSAFE and is provided for convenience only. Without this
         * capability the server would have to be started in foreground mode.
         */
        if ((*parg->mc->pphrase_dialog_path != '\0') &&
           ((pwd_fileptr = fopen(parg->mc->pphrase_dialog_path, "r")) != NULL)) {
            while(fgets(line, 1024, pwd_fileptr)) {
                if (PL_strstr(line, token_name) == line) {
                    tmp = PL_strlen(line) - 1;
                    while((line[tmp] == ' ') || (line[tmp] == '\n'))
                        tmp--;
                    line[tmp+1] = '\0';
                    ptr = PL_strchr(line, ':');
                    if (ptr == NULL) {
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, parg->s,
                           "Malformed password entry for token %s. Format should be token:password", token_name);
                        continue;
                    }
                    for(tmp=1; ptr[tmp] == ' '; tmp++) {}
                    pwdstr = strdup(&(ptr[tmp]));
                }
            }
            fclose(pwd_fileptr);
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parg->s,
                 "Unable to open password file %s", parg->mc->pphrase_dialog_path);
            nss_die();
        }
    } else if ((parg->mc->pphrase_dialog_type == SSL_PPTYPE_FILTER) &&
                (parg->mc->nInitCount == 1)) {
        /* We only have tty during first module load */
        const char *cmd = parg->mc->pphrase_dialog_path;
        const char **argv = apr_palloc(parg->mc->pPool, sizeof(char *) * 4);
        char *result;
        int i;

        ap_log_error(APLOG_MARK, APLOG_INFO, 0, parg->s,
                     "Requesting pass phrase from dialog filter "
                     "program (%s)", cmd);

        argv[0] = cmd;
        argv[1] = token_name;
        argv[2] = "NSS";
        argv[3] = NULL;

        result = nss_util_readfilter(NULL, parg->mc->pPool, cmd, argv);

        /* readfilter returns NULL in case of ANY error */
        if (NULL != result)
            pwdstr = strdup(result);
    }

    /* For SSL_PPTYPE_DEFER we only want to authenticate passwords found
     * in the password file.
     */
    if ((parg->mc->pphrase_dialog_type == SSL_PPTYPE_DEFER) &&
        (pwdstr == NULL)) {
        return NULL;
    }

    /* This purposely comes after the file check because that is more
     * authoritative.
     */
    if (parg->mc->nInitCount > 1) {
        char buf[1024];
        apr_status_t rv;
        apr_size_t nBytes = 1024;
        struct sembuf sb;

        /* lock the pipe */
        sb.sem_num = 0;
        sb.sem_op = -1;
        sb.sem_flg = SEM_UNDO;
        if (semop(parg->mc->semid, &sb, 1) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parg->s,
                "Unable to reserve semaphore resource");
        }

        snprintf(buf, 1024, "RETR\t%s", token_name);
        rv = apr_file_write_full(parg->mc->proc.in, buf, strlen(buf), NULL);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parg->s,
                "Unable to write to pin store for slot: %s APR err: %d",  PK11_GetTokenName(slot), rv);
            nss_die();
        }

        /* The helper just returns a token pw or "", so we don't have much
         * to check for.
         */
        memset(buf, 0, sizeof(buf));
        rv = apr_file_read(parg->mc->proc.out, buf, &nBytes);
        sb.sem_op = 1;
        if (semop(parg->mc->semid, &sb, 1) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parg->s,
                "Unable to free semaphore resource");
            /* perror("semop free resource id"); */
        }

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parg->s,
                "Unable to read from pin store for slot: %s APR err: %d",  PK11_GetTokenName(slot), rv);
            nss_die();
        }

        /* Just return what we got. If we got this far and we don't have a
         * PIN then I/O is already shut down, so we can't do anything really
         * clever.
         */
        pwdstr = strdup(buf);
    }

    /* If we got a password we're done */
    if (pwdstr)
        return pwdstr;

    for (;;) {
        /* Prompt for password */
        if (isTTY) {
            if (parg->retryCount > 0) {
                fprintf(output, "Password incorrect. Please try again.\n");
            }
            fprintf(output, "%s", prompt);
            echoOff(infd);
        }
        fgets((char*) phrase, sizeof(phrase), input);
        if (isTTY) {
            fprintf(output, "\n");
            echoOn(infd);
        }
        /* stomp on newline */
        phrase[strlen((char*)phrase)-1] = 0;

        /* Validate password */
        if (!(*ok)(phrase)) {
            /* Not weird enough */
            if (!isTTY) return 0;
            fprintf(output, "Password must be at least 8 characters long with one or more\n");
            fprintf(output, "non-alphabetic characters\n");
            continue;
        }
        if (PK11_IsFIPS() && strlen((char *)phrase) == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parg->s,
                "The FIPS security policy requires that a password be set.");
            nss_die();
        } else
            return (char*) PORT_Strdup((char*)phrase);
    }
}

/*
 * Turn the echoing off on a tty.
 */
static void echoOff(int fd)
{
    if (isatty(fd)) {
        struct termios tio;
        tcgetattr(fd, &tio);
        tio.c_lflag &= ~ECHO;
        tcsetattr(fd, TCSAFLUSH, &tio);
    }
}

/*
 * Turn the echoing on on a tty.
 */
static void echoOn(int fd)
{
    if (isatty(fd)) {
        struct termios tio;
        tcgetattr(fd, &tio);
        tio.c_lflag |= ECHO;
        tcsetattr(fd, TCSAFLUSH, &tio);
    }
}
