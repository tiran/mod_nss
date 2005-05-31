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

/*  _________________________________________________________________
**
**  Expression Parser
**  _________________________________________________________________
*/

%{
#include "mod_nss.h"
%}

%union {
    char     *cpVal;
    nss_expr *exVal;
}

%token  T_TRUE
%token  T_FALSE

%token  <cpVal> T_DIGIT
%token  <cpVal> T_ID
%token  <cpVal> T_STRING
%token  <cpVal> T_REGEX
%token  <cpVal> T_REGEX_I

%token  T_FUNC_FILE

%token  T_OP_EQ
%token  T_OP_NE
%token  T_OP_LT
%token  T_OP_LE
%token  T_OP_GT
%token  T_OP_GE
%token  T_OP_REG
%token  T_OP_NRE
%token  T_OP_IN

%token  T_OP_OR
%token  T_OP_AND
%token  T_OP_NOT

%left   T_OP_OR
%left   T_OP_AND
%left   T_OP_NOT

%type   <exVal>   expr
%type   <exVal>   comparison
%type   <exVal>   funccall
%type   <exVal>   regex
%type   <exVal>   words
%type   <exVal>   word

%%

root      : expr                         { nss_expr_info.expr = $1; }
          ;

expr      : T_TRUE                       { $$ = nss_expr_make(op_True,  NULL, NULL); }
          | T_FALSE                      { $$ = nss_expr_make(op_False, NULL, NULL); }
          | T_OP_NOT expr                { $$ = nss_expr_make(op_Not,   $2,   NULL); }
          | expr T_OP_OR expr            { $$ = nss_expr_make(op_Or,    $1,   $3);   }
          | expr T_OP_AND expr           { $$ = nss_expr_make(op_And,   $1,   $3);   }
          | comparison                   { $$ = nss_expr_make(op_Comp,  $1,   NULL); }
          | '(' expr ')'                 { $$ = $2; }
          ;

comparison: word T_OP_EQ word            { $$ = nss_expr_make(op_EQ,  $1, $3); }
          | word T_OP_NE word            { $$ = nss_expr_make(op_NE,  $1, $3); }
          | word T_OP_LT word            { $$ = nss_expr_make(op_LT,  $1, $3); }
          | word T_OP_LE word            { $$ = nss_expr_make(op_LE,  $1, $3); }
          | word T_OP_GT word            { $$ = nss_expr_make(op_GT,  $1, $3); }
          | word T_OP_GE word            { $$ = nss_expr_make(op_GE,  $1, $3); }
          | word T_OP_IN '{' words '}'   { $$ = nss_expr_make(op_IN,  $1, $4); }
          | word T_OP_REG regex          { $$ = nss_expr_make(op_REG, $1, $3); }
          | word T_OP_NRE regex          { $$ = nss_expr_make(op_NRE, $1, $3); }
          ;

words     : word                         { $$ = nss_expr_make(op_ListElement, $1, NULL); }
          | words ',' word               { $$ = nss_expr_make(op_ListElement, $3, $1);   }
          ;

word      : T_DIGIT                      { $$ = nss_expr_make(op_Digit,  $1, NULL); }
          | T_STRING                     { $$ = nss_expr_make(op_String, $1, NULL); }
          | '%' '{' T_ID '}'             { $$ = nss_expr_make(op_Var,    $3, NULL); }
          | funccall                     { $$ = $1; }
          ;

regex     : T_REGEX { 
                regex_t *regex;
                if ((regex = ap_pregcomp(nss_expr_info.pool, $1, 
                                         REG_EXTENDED|REG_NOSUB)) == NULL) {
                    nss_expr_error = "Failed to compile regular expression";
                    YYERROR;
                }
                $$ = nss_expr_make(op_Regex, regex, NULL);
            }
          | T_REGEX_I {
                regex_t *regex;
                if ((regex = ap_pregcomp(nss_expr_info.pool, $1, 
                                         REG_EXTENDED|REG_NOSUB|REG_ICASE)) == NULL) {
                    nss_expr_error = "Failed to compile regular expression";
                    YYERROR;
                }
                $$ = nss_expr_make(op_Regex, regex, NULL);
            }
          ;

funccall  : T_FUNC_FILE '(' T_STRING ')' { 
               nss_expr *args = nss_expr_make(op_ListElement, $3, NULL);
               $$ = nss_expr_make(op_Func, "file", args);
            }
          ;

%%

int yyerror(char *s)
{
    nss_expr_error = s;
    return 2;
}

