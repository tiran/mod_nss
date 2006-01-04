/* A Bison parser, made by GNU Bison 1.875c.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum nss_expr_yytokentype {
     T_TRUE = 258,
     T_FALSE = 259,
     T_DIGIT = 260,
     T_ID = 261,
     T_STRING = 262,
     T_REGEX = 263,
     T_REGEX_I = 264,
     T_FUNC_FILE = 265,
     T_OP_EQ = 266,
     T_OP_NE = 267,
     T_OP_LT = 268,
     T_OP_LE = 269,
     T_OP_GT = 270,
     T_OP_GE = 271,
     T_OP_REG = 272,
     T_OP_NRE = 273,
     T_OP_IN = 274,
     T_OP_OR = 275,
     T_OP_AND = 276,
     T_OP_NOT = 277
   };
#endif
#define T_TRUE 258
#define T_FALSE 259
#define T_DIGIT 260
#define T_ID 261
#define T_STRING 262
#define T_REGEX 263
#define T_REGEX_I 264
#define T_FUNC_FILE 265
#define T_OP_EQ 266
#define T_OP_NE 267
#define T_OP_LT 268
#define T_OP_LE 269
#define T_OP_GT 270
#define T_OP_GE 271
#define T_OP_REG 272
#define T_OP_NRE 273
#define T_OP_IN 274
#define T_OP_OR 275
#define T_OP_AND 276
#define T_OP_NOT 277




#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 26 "nss_expr_parse.y"
typedef union YYSTYPE {
    char     *cpVal;
    nss_expr *exVal;
} YYSTYPE;
/* Line 1275 of yacc.c.  */
#line 86 "y.tab.h"
# define nss_expr_yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE nss_expr_yylval;



