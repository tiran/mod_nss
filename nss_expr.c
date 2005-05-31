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
**  Expression Handling
**  _________________________________________________________________
*/

nss_expr_info_type nss_expr_info;
char              *nss_expr_error;

nss_expr *nss_expr_comp(apr_pool_t *p, char *expr)
{
    nss_expr_info.pool       = p;
    nss_expr_info.inputbuf   = expr;
    nss_expr_info.inputlen   = strlen(expr);
    nss_expr_info.inputptr   = nss_expr_info.inputbuf;
    nss_expr_info.expr       = FALSE;

    nss_expr_error = NULL;
    if (nss_expr_yyparse())
        return NULL;
    return nss_expr_info.expr;
}

char *nss_expr_get_error(void)
{
    if (nss_expr_error == NULL)
        return "";
    return nss_expr_error;
}

nss_expr *nss_expr_make(nss_expr_node_op op, void *a1, void *a2)
{
    nss_expr *node;

    node = (nss_expr *)apr_palloc(nss_expr_info.pool, sizeof(nss_expr));
    node->node_op   = op;
    node->node_arg1 = (char *)a1;
    node->node_arg2 = (char *)a2;
    return node;
}

int nss_expr_exec(request_rec *r, nss_expr *expr)
{
    BOOL rc;

    rc = nss_expr_eval(r, expr);
    if (nss_expr_error != NULL)
        return (-1);
    else
        return (rc ? 1 : 0);
}
