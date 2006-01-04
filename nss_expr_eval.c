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
**  Expression Evaluation
**  _________________________________________________________________
*/

static BOOL  nss_expr_eval_comp(request_rec *, nss_expr *);
static char *nss_expr_eval_word(request_rec *, nss_expr *);
static char *nss_expr_eval_func_file(request_rec *, char *);
static int   nss_expr_eval_strcmplex(char *, char *);

BOOL nss_expr_eval(request_rec *r, nss_expr *node)
{
    switch (node->node_op) {
        case op_True: {
            return TRUE;
        }
        case op_False: {
            return FALSE;
        }
        case op_Not: {
            nss_expr *e = (nss_expr *)node->node_arg1;
            return (!nss_expr_eval(r, e));
        }
        case op_Or: {
            nss_expr *e1 = (nss_expr *)node->node_arg1;
            nss_expr *e2 = (nss_expr *)node->node_arg2;
            return (nss_expr_eval(r, e1) || nss_expr_eval(r, e2));
        }
        case op_And: {
            nss_expr *e1 = (nss_expr *)node->node_arg1;
            nss_expr *e2 = (nss_expr *)node->node_arg2;
            return (nss_expr_eval(r, e1) && nss_expr_eval(r, e2));
        }
        case op_Comp: {
            nss_expr *e = (nss_expr *)node->node_arg1;
            return nss_expr_eval_comp(r, e);
        }
        default: {
            nss_expr_error = "Internal evaluation error: Unknown expression node";
            return FALSE;
        }
    }
}

static BOOL nss_expr_eval_comp(request_rec *r, nss_expr *node)
{
    switch (node->node_op) {
        case op_EQ: {
            nss_expr *e1 = (nss_expr *)node->node_arg1;
            nss_expr *e2 = (nss_expr *)node->node_arg2;
            return (strcmp(nss_expr_eval_word(r, e1), nss_expr_eval_word(r, e2)) == 0);
        }
        case op_NE: {
            nss_expr *e1 = (nss_expr *)node->node_arg1;
            nss_expr *e2 = (nss_expr *)node->node_arg2;
            return (strcmp(nss_expr_eval_word(r, e1), nss_expr_eval_word(r, e2)) != 0);
        }
        case op_LT: {
            nss_expr *e1 = (nss_expr *)node->node_arg1;
            nss_expr *e2 = (nss_expr *)node->node_arg2;
            return (nss_expr_eval_strcmplex(nss_expr_eval_word(r, e1), nss_expr_eval_word(r, e2)) <  0);
        }
        case op_LE: {
            nss_expr *e1 = (nss_expr *)node->node_arg1;
            nss_expr *e2 = (nss_expr *)node->node_arg2;
            return (nss_expr_eval_strcmplex(nss_expr_eval_word(r, e1), nss_expr_eval_word(r, e2)) <= 0);
        }
        case op_GT: {
            nss_expr *e1 = (nss_expr *)node->node_arg1;
            nss_expr *e2 = (nss_expr *)node->node_arg2;
            return (nss_expr_eval_strcmplex(nss_expr_eval_word(r, e1), nss_expr_eval_word(r, e2)) >  0);
        }
        case op_GE: {
            nss_expr *e1 = (nss_expr *)node->node_arg1;
            nss_expr *e2 = (nss_expr *)node->node_arg2;
            return (nss_expr_eval_strcmplex(nss_expr_eval_word(r, e1), nss_expr_eval_word(r, e2)) >= 0);
        }
        case op_IN: {
            nss_expr *e1 = (nss_expr *)node->node_arg1;
            nss_expr *e2 = (nss_expr *)node->node_arg2;
            nss_expr *e3;
            char *w1 = nss_expr_eval_word(r, e1);
            BOOL found = FALSE;
            do {
                e3 = (nss_expr *)e2->node_arg1;
                e2 = (nss_expr *)e2->node_arg2;
                if (strcmp(w1, nss_expr_eval_word(r, e3)) == 0) {
                    found = TRUE;
                    break;
                }
            } while (e2 != NULL);
            return found;
        }
        case op_REG: {
            nss_expr *e1;
            nss_expr *e2;
            char *word;
            ap_regex_t *regex;

            e1 = (nss_expr *)node->node_arg1;
            e2 = (nss_expr *)node->node_arg2;
            word = nss_expr_eval_word(r, e1);
            regex = (ap_regex_t *)(e2->node_arg1);
            return (ap_regexec(regex, word, 0, NULL, 0) == 0);
        }
        case op_NRE: {
            nss_expr *e1;
            nss_expr *e2;
            char *word;
            ap_regex_t *regex;

            e1 = (nss_expr *)node->node_arg1;
            e2 = (nss_expr *)node->node_arg2;
            word = nss_expr_eval_word(r, e1);
            regex = (ap_regex_t *)(e2->node_arg1);
            return !(ap_regexec(regex, word, 0, NULL, 0) == 0);
        }
        default: {
            nss_expr_error = "Internal evaluation error: Unknown expression node";
            return FALSE;
        }
    }
}

static char *nss_expr_eval_word(request_rec *r, nss_expr *node)
{
    switch (node->node_op) {
        case op_Digit: {
            char *string = (char *)node->node_arg1;
            return string;
        }
        case op_String: {
            char *string = (char *)node->node_arg1;
            return string;
        }
        case op_Var: {
            char *var = (char *)node->node_arg1;
            char *val = nss_var_lookup(r->pool, r->server, r->connection, r, var);
            return (val == NULL ? "" : val);
        }
        case op_Func: {
            char *name = (char *)node->node_arg1;
            nss_expr *args = (nss_expr *)node->node_arg2;
            if (strEQ(name, "file"))
                return nss_expr_eval_func_file(r, (char *)(args->node_arg1));
            else {
                nss_expr_error = "Internal evaluation error: Unknown function name";
                return "";
            }
        }
        default: {
            nss_expr_error = "Internal evaluation error: Unknown expression node";
            return FALSE;
        }
    }
}

static char *nss_expr_eval_func_file(request_rec *r, char *filename)
{
    apr_file_t *fp;
    char *buf;
    apr_off_t offset;
    apr_size_t len;
    apr_finfo_t finfo;

    if (apr_file_open(&fp, filename, APR_READ|APR_BUFFERED, 
                      APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
        nss_expr_error = "Cannot open file";
        return "";
    }
    apr_file_info_get(&finfo, APR_FINFO_SIZE, fp);
    if ((finfo.size + 1) != ((apr_size_t)finfo.size + 1)) {
        nss_expr_error = "Huge file cannot be read";
        apr_file_close(fp);
        return "";
    }
    len = (apr_size_t)finfo.size;
    if (len == 0) {
        buf = (char *)apr_palloc(r->pool, sizeof(char) * 1);
        *buf = NUL;
    }
    else {
        if ((buf = (char *)apr_palloc(r->pool, sizeof(char)*(len+1))) == NULL) {
            nss_expr_error = "Cannot allocate memory";
            apr_file_close(fp);
            return "";
        }
        offset = 0;
        apr_file_seek(fp, APR_SET, &offset);
        if (apr_file_read(fp, buf, &len) != APR_SUCCESS) {
            nss_expr_error = "Cannot read from file";
            apr_file_close(fp);
            return "";
        }
        buf[len] = NUL;
    }
    apr_file_close(fp);
    return buf;
}

/* a variant of strcmp(3) which works correctly also for number strings */
static int nss_expr_eval_strcmplex(char *cpNum1, char *cpNum2)
{
    int i, n1, n2;

    if (cpNum1 == NULL)
        return -1;
    if (cpNum2 == NULL)
        return +1;
    n1 = strlen(cpNum1);
    n2 = strlen(cpNum2);
    if (n1 > n2)
        return 1;
    if (n1 < n2)
        return -1;
    for (i = 0; i < n1; i++) {
        if (cpNum1[i] > cpNum2[i])
            return 1;
        if (cpNum1[i] < cpNum2[i])
            return -1;
    }
    return 0;
}
