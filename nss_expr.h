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

#ifndef __NSS_EXPR_H__
#define __NSS_EXPR_H__

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

#ifndef YY_NULL
#define YY_NULL 0
#endif

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef BOOL
#define BOOL unsigned int
#endif

#ifndef NULL
#define NULL (void *)0
#endif

#ifndef NUL
#define NUL '\0'
#endif

#ifndef YYDEBUG
#define YYDEBUG 0
#endif

typedef enum {
    op_NOP, op_ListElement,
    op_True, op_False, op_Not, op_Or, op_And, op_Comp,
    op_EQ, op_NE, op_LT, op_LE, op_GT, op_GE, op_IN, op_REG, op_NRE,
    op_Digit, op_String, op_Regex, op_Var, op_Func
} nss_expr_node_op;

typedef struct {
    nss_expr_node_op node_op;
    void *node_arg1;
    void *node_arg2;
    apr_pool_t *p;
} nss_expr_node;

typedef nss_expr_node nss_expr;

typedef struct {
	apr_pool_t *pool;
    char     *inputbuf;
    int       inputlen;
    char     *inputptr;
    nss_expr *expr;
} nss_expr_info_type;

extern nss_expr_info_type nss_expr_info;
extern char *nss_expr_error;

#define yylval  nss_expr_yylval
#define yyerror nss_expr_yyerror
#define yyinput nss_expr_yyinput

extern int nss_expr_yyparse(void);
extern int nss_expr_yyerror(char *);
extern int nss_expr_yylex(void);

extern nss_expr *nss_expr_comp(apr_pool_t *, char *);
extern int       nss_expr_exec(request_rec *, nss_expr *);
extern char     *nss_expr_get_error(void);
extern nss_expr *nss_expr_make(nss_expr_node_op, void *, void *);
extern BOOL      nss_expr_eval(request_rec *, nss_expr *);

#endif /* __NSS_EXPR_H__ */
