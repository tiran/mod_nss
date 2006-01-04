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

/* Written by Richard Stallman by simplifying the original so called
   ``semantic'' parser.  */

/* All symbols defined below should begin with nss_expr_yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0



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




/* Copy the first part of user declarations.  */
#line 22 "nss_expr_parse.y"

#include "mod_nss.h"


/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 26 "nss_expr_parse.y"
typedef union YYSTYPE {
    char     *cpVal;
    nss_expr *exVal;
} YYSTYPE;
/* Line 191 of yacc.c.  */
#line 129 "y.tab.c"
# define nss_expr_yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 214 of yacc.c.  */
#line 141 "y.tab.c"

#if ! defined (nss_expr_yyoverflow) || YYERROR_VERBOSE

# ifndef YYFREE
#  define YYFREE free
# endif
# ifndef YYMALLOC
#  define YYMALLOC malloc
# endif

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   define YYSTACK_ALLOC alloca
#  endif
# else
#  if defined (alloca) || defined (_ALLOCA_H)
#   define YYSTACK_ALLOC alloca
#  else
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
# endif
#endif /* ! defined (nss_expr_yyoverflow) || YYERROR_VERBOSE */


#if (! defined (nss_expr_yyoverflow) \
     && (! defined (__cplusplus) \
	 || (defined (YYSTYPE_IS_TRIVIAL) && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union nss_expr_yyalloc
{
  short nss_expr_yyss;
  YYSTYPE nss_expr_yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union nss_expr_yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE))				\
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined (__GNUC__) && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  register YYSIZE_T nss_expr_yyi;		\
	  for (nss_expr_yyi = 0; nss_expr_yyi < (Count); nss_expr_yyi++)	\
	    (To)[nss_expr_yyi] = (From)[nss_expr_yyi];		\
	}					\
      while (0)
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T nss_expr_yynewbytes;						\
	YYCOPY (&nss_expr_yyptr->Stack, Stack, nss_expr_yysize);				\
	Stack = &nss_expr_yyptr->Stack;						\
	nss_expr_yynewbytes = nss_expr_yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	nss_expr_yyptr += nss_expr_yynewbytes / sizeof (*nss_expr_yyptr);				\
      }									\
    while (0)

#endif

#if defined (__STDC__) || defined (__cplusplus)
   typedef signed char nss_expr_yysigned_char;
#else
   typedef short nss_expr_yysigned_char;
#endif

/* YYFINAL -- State number of the termination state. */
#define YYFINAL  18
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   52

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  29
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  8
/* YYNRULES -- Number of rules. */
#define YYNRULES  27
/* YYNRULES -- Number of states. */
#define YYNSTATES  53

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   277

#define YYTRANSLATE(YYX) 						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? nss_expr_yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned char nss_expr_yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,    28,     2,     2,
      23,    24,     2,     2,    27,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    25,     2,    26,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned char nss_expr_yyprhs[] =
{
       0,     0,     3,     5,     7,     9,    12,    16,    20,    22,
      26,    30,    34,    38,    42,    46,    50,    56,    60,    64,
      66,    70,    72,    74,    79,    81,    83,    85
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const nss_expr_yysigned_char nss_expr_yyrhs[] =
{
      30,     0,    -1,    31,    -1,     3,    -1,     4,    -1,    22,
      31,    -1,    31,    20,    31,    -1,    31,    21,    31,    -1,
      32,    -1,    23,    31,    24,    -1,    34,    11,    34,    -1,
      34,    12,    34,    -1,    34,    13,    34,    -1,    34,    14,
      34,    -1,    34,    15,    34,    -1,    34,    16,    34,    -1,
      34,    19,    25,    33,    26,    -1,    34,    17,    35,    -1,
      34,    18,    35,    -1,    34,    -1,    33,    27,    34,    -1,
       5,    -1,     7,    -1,    28,    25,     6,    26,    -1,    36,
      -1,     8,    -1,     9,    -1,    10,    23,     7,    24,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned char nss_expr_yyrline[] =
{
       0,    69,    69,    72,    73,    74,    75,    76,    77,    78,
      81,    82,    83,    84,    85,    86,    87,    88,    89,    92,
      93,    96,    97,    98,    99,   102,   111,   122
};
#endif

#if YYDEBUG || YYERROR_VERBOSE
/* YYTNME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
static const char *const nss_expr_yytname[] =
{
  "$end", "error", "$undefined", "T_TRUE", "T_FALSE", "T_DIGIT", "T_ID",
  "T_STRING", "T_REGEX", "T_REGEX_I", "T_FUNC_FILE", "T_OP_EQ", "T_OP_NE",
  "T_OP_LT", "T_OP_LE", "T_OP_GT", "T_OP_GE", "T_OP_REG", "T_OP_NRE",
  "T_OP_IN", "T_OP_OR", "T_OP_AND", "T_OP_NOT", "'('", "')'", "'{'", "'}'",
  "','", "'%'", "$accept", "root", "expr", "comparison", "words", "word",
  "regex", "funccall", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const unsigned short nss_expr_yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,    40,    41,   123,   125,    44,    37
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char nss_expr_yyr1[] =
{
       0,    29,    30,    31,    31,    31,    31,    31,    31,    31,
      32,    32,    32,    32,    32,    32,    32,    32,    32,    33,
      33,    34,    34,    34,    34,    35,    35,    36
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char nss_expr_yyr2[] =
{
       0,     2,     1,     1,     1,     2,     3,     3,     1,     3,
       3,     3,     3,     3,     3,     3,     5,     3,     3,     1,
       3,     1,     1,     4,     1,     1,     1,     4
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char nss_expr_yydefact[] =
{
       0,     3,     4,    21,    22,     0,     0,     0,     0,     0,
       2,     8,     0,    24,     0,     5,     0,     0,     1,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     9,     0,     6,     7,    10,    11,    12,    13,    14,
      15,    25,    26,    17,    18,     0,    27,    23,     0,    19,
      16,     0,    20
};

/* YYDEFGOTO[NTERM-NUM]. */
static const nss_expr_yysigned_char nss_expr_yydefgoto[] =
{
      -1,     9,    10,    11,    48,    12,    43,    13
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -22
static const nss_expr_yysigned_char nss_expr_yypact[] =
{
       3,   -22,   -22,   -22,   -22,   -11,     3,     3,     2,    44,
      -1,   -22,    22,   -22,    38,   -22,    -3,    40,   -22,     3,
       3,     4,     4,     4,     4,     4,     4,    14,    14,    23,
      25,   -22,    21,    29,   -22,   -22,   -22,   -22,   -22,   -22,
     -22,   -22,   -22,   -22,   -22,     4,   -22,   -22,    16,   -22,
     -22,     4,   -22
};

/* YYPGOTO[NTERM-NUM].  */
static const nss_expr_yysigned_char nss_expr_yypgoto[] =
{
     -22,   -22,     9,   -22,   -22,   -21,    24,   -22
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const unsigned char nss_expr_yytable[] =
{
      35,    36,    37,    38,    39,    40,     1,     2,     3,     3,
       4,     4,    14,     5,     5,    15,    16,    19,    20,    19,
      20,    31,    41,    42,    49,     6,     7,    17,    33,    34,
      52,     8,     8,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    50,    51,    18,    30,    32,    47,    45,    46,
      20,     0,    44
};

static const nss_expr_yysigned_char nss_expr_yycheck[] =
{
      21,    22,    23,    24,    25,    26,     3,     4,     5,     5,
       7,     7,    23,    10,    10,     6,     7,    20,    21,    20,
      21,    24,     8,     9,    45,    22,    23,    25,    19,    20,
      51,    28,    28,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    26,    27,     0,     7,     6,    26,    25,    24,
      21,    -1,    28
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char nss_expr_yystos[] =
{
       0,     3,     4,     5,     7,    10,    22,    23,    28,    30,
      31,    32,    34,    36,    23,    31,    31,    25,     0,    20,
      21,    11,    12,    13,    14,    15,    16,    17,    18,    19,
       7,    24,     6,    31,    31,    34,    34,    34,    34,    34,
      34,     8,     9,    35,    35,    25,    24,    26,    33,    34,
      26,    27,    34
};

#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define nss_expr_yyerrok		(nss_expr_yyerrstatus = 0)
#define nss_expr_yyclearin	(nss_expr_yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto nss_expr_yyacceptlab
#define YYABORT		goto nss_expr_yyabortlab
#define YYERROR		goto nss_expr_yyerrorlab


/* Like YYERROR except do call nss_expr_yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto nss_expr_yyerrlab

#define YYRECOVERING()  (!!nss_expr_yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (nss_expr_yychar == YYEMPTY && nss_expr_yylen == 1)				\
    {								\
      nss_expr_yychar = (Token);						\
      nss_expr_yylval = (Value);						\
      nss_expr_yytoken = YYTRANSLATE (nss_expr_yychar);				\
      YYPOPSTACK;						\
      goto nss_expr_yybackup;						\
    }								\
  else								\
    { 								\
      nss_expr_yyerror ("syntax error: cannot back up");\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)		\
   ((Current).first_line   = (Rhs)[1].first_line,	\
    (Current).first_column = (Rhs)[1].first_column,	\
    (Current).last_line    = (Rhs)[N].last_line,	\
    (Current).last_column  = (Rhs)[N].last_column)
#endif

/* YYLEX -- calling `nss_expr_yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX nss_expr_yylex (YYLEX_PARAM)
#else
# define YYLEX nss_expr_yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (nss_expr_yydebug)					\
    YYFPRINTF Args;				\
} while (0)

# define YYDSYMPRINT(Args)			\
do {						\
  if (nss_expr_yydebug)					\
    nss_expr_yysymprint Args;				\
} while (0)

# define YYDSYMPRINTF(Title, Token, Value, Location)		\
do {								\
  if (nss_expr_yydebug)							\
    {								\
      YYFPRINTF (stderr, "%s ", Title);				\
      nss_expr_yysymprint (stderr, 					\
                  Token, Value);	\
      YYFPRINTF (stderr, "\n");					\
    }								\
} while (0)

/*------------------------------------------------------------------.
| nss_expr_yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
nss_expr_yy_stack_print (short *bottom, short *top)
#else
static void
nss_expr_yy_stack_print (bottom, top)
    short *bottom;
    short *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (/* Nothing. */; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (nss_expr_yydebug)							\
    nss_expr_yy_stack_print ((Bottom), (Top));				\
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
nss_expr_yy_reduce_print (int nss_expr_yyrule)
#else
static void
nss_expr_yy_reduce_print (nss_expr_yyrule)
    int nss_expr_yyrule;
#endif
{
  int nss_expr_yyi;
  unsigned int nss_expr_yylno = nss_expr_yyrline[nss_expr_yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %u), ",
             nss_expr_yyrule - 1, nss_expr_yylno);
  /* Print the symbols being reduced, and their result.  */
  for (nss_expr_yyi = nss_expr_yyprhs[nss_expr_yyrule]; 0 <= nss_expr_yyrhs[nss_expr_yyi]; nss_expr_yyi++)
    YYFPRINTF (stderr, "%s ", nss_expr_yytname [nss_expr_yyrhs[nss_expr_yyi]]);
  YYFPRINTF (stderr, "-> %s\n", nss_expr_yytname [nss_expr_yyr1[nss_expr_yyrule]]);
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (nss_expr_yydebug)				\
    nss_expr_yy_reduce_print (Rule);		\
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int nss_expr_yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YYDSYMPRINT(Args)
# define YYDSYMPRINTF(Title, Token, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if defined (YYMAXDEPTH) && YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef nss_expr_yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define nss_expr_yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
nss_expr_yystrlen (const char *nss_expr_yystr)
#   else
nss_expr_yystrlen (nss_expr_yystr)
     const char *nss_expr_yystr;
#   endif
{
  register const char *nss_expr_yys = nss_expr_yystr;

  while (*nss_expr_yys++ != '\0')
    continue;

  return nss_expr_yys - nss_expr_yystr - 1;
}
#  endif
# endif

# ifndef nss_expr_yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define nss_expr_yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
nss_expr_yystpcpy (char *nss_expr_yydest, const char *nss_expr_yysrc)
#   else
nss_expr_yystpcpy (nss_expr_yydest, nss_expr_yysrc)
     char *nss_expr_yydest;
     const char *nss_expr_yysrc;
#   endif
{
  register char *nss_expr_yyd = nss_expr_yydest;
  register const char *nss_expr_yys = nss_expr_yysrc;

  while ((*nss_expr_yyd++ = *nss_expr_yys++) != '\0')
    continue;

  return nss_expr_yyd - 1;
}
#  endif
# endif

#endif /* !YYERROR_VERBOSE */



#if YYDEBUG
/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
nss_expr_yysymprint (FILE *nss_expr_yyoutput, int nss_expr_yytype, YYSTYPE *nss_expr_yyvaluep)
#else
static void
nss_expr_yysymprint (nss_expr_yyoutput, nss_expr_yytype, nss_expr_yyvaluep)
    FILE *nss_expr_yyoutput;
    int nss_expr_yytype;
    YYSTYPE *nss_expr_yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) nss_expr_yyvaluep;

  if (nss_expr_yytype < YYNTOKENS)
    {
      YYFPRINTF (nss_expr_yyoutput, "token %s (", nss_expr_yytname[nss_expr_yytype]);
# ifdef YYPRINT
      YYPRINT (nss_expr_yyoutput, nss_expr_yytoknum[nss_expr_yytype], *nss_expr_yyvaluep);
# endif
    }
  else
    YYFPRINTF (nss_expr_yyoutput, "nterm %s (", nss_expr_yytname[nss_expr_yytype]);

  switch (nss_expr_yytype)
    {
      default:
        break;
    }
  YYFPRINTF (nss_expr_yyoutput, ")");
}

#endif /* ! YYDEBUG */
/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
nss_expr_yydestruct (int nss_expr_yytype, YYSTYPE *nss_expr_yyvaluep)
#else
static void
nss_expr_yydestruct (nss_expr_yytype, nss_expr_yyvaluep)
    int nss_expr_yytype;
    YYSTYPE *nss_expr_yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) nss_expr_yyvaluep;

  switch (nss_expr_yytype)
    {

      default:
        break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int nss_expr_yyparse (void *YYPARSE_PARAM);
# else
int nss_expr_yyparse ();
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int nss_expr_yyparse (void);
#else
int nss_expr_yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */



/* The lookahead symbol.  */
int nss_expr_yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE nss_expr_yylval;

/* Number of syntax errors so far.  */
int nss_expr_yynerrs;



/*----------.
| nss_expr_yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int nss_expr_yyparse (void *YYPARSE_PARAM)
# else
int nss_expr_yyparse (YYPARSE_PARAM)
  void *YYPARSE_PARAM;
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int
nss_expr_yyparse (void)
#else
int
nss_expr_yyparse ()

#endif
#endif
{
  
  register int nss_expr_yystate;
  register int nss_expr_yyn;
  int nss_expr_yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int nss_expr_yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int nss_expr_yytoken = 0;

  /* Three stacks and their tools:
     `nss_expr_yyss': related to states,
     `nss_expr_yyvs': related to semantic values,
     `nss_expr_yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow nss_expr_yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  short	nss_expr_yyssa[YYINITDEPTH];
  short *nss_expr_yyss = nss_expr_yyssa;
  register short *nss_expr_yyssp;

  /* The semantic value stack.  */
  YYSTYPE nss_expr_yyvsa[YYINITDEPTH];
  YYSTYPE *nss_expr_yyvs = nss_expr_yyvsa;
  register YYSTYPE *nss_expr_yyvsp;



#define YYPOPSTACK   (nss_expr_yyvsp--, nss_expr_yyssp--)

  YYSIZE_T nss_expr_yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE nss_expr_yyval;


  /* When reducing, the number of symbols on the RHS of the reduced
     rule.  */
  int nss_expr_yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  nss_expr_yystate = 0;
  nss_expr_yyerrstatus = 0;
  nss_expr_yynerrs = 0;
  nss_expr_yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  nss_expr_yyssp = nss_expr_yyss;
  nss_expr_yyvsp = nss_expr_yyvs;

  goto nss_expr_yysetstate;

/*------------------------------------------------------------.
| nss_expr_yynewstate -- Push a new state, which is found in nss_expr_yystate.  |
`------------------------------------------------------------*/
 nss_expr_yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  nss_expr_yyssp++;

 nss_expr_yysetstate:
  *nss_expr_yyssp = nss_expr_yystate;

  if (nss_expr_yyss + nss_expr_yystacksize - 1 <= nss_expr_yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T nss_expr_yysize = nss_expr_yyssp - nss_expr_yyss + 1;

#ifdef nss_expr_yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *nss_expr_yyvs1 = nss_expr_yyvs;
	short *nss_expr_yyss1 = nss_expr_yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if nss_expr_yyoverflow is a macro.  */
	nss_expr_yyoverflow ("parser stack overflow",
		    &nss_expr_yyss1, nss_expr_yysize * sizeof (*nss_expr_yyssp),
		    &nss_expr_yyvs1, nss_expr_yysize * sizeof (*nss_expr_yyvsp),

		    &nss_expr_yystacksize);

	nss_expr_yyss = nss_expr_yyss1;
	nss_expr_yyvs = nss_expr_yyvs1;
      }
#else /* no nss_expr_yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto nss_expr_yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= nss_expr_yystacksize)
	goto nss_expr_yyoverflowlab;
      nss_expr_yystacksize *= 2;
      if (YYMAXDEPTH < nss_expr_yystacksize)
	nss_expr_yystacksize = YYMAXDEPTH;

      {
	short *nss_expr_yyss1 = nss_expr_yyss;
	union nss_expr_yyalloc *nss_expr_yyptr =
	  (union nss_expr_yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (nss_expr_yystacksize));
	if (! nss_expr_yyptr)
	  goto nss_expr_yyoverflowlab;
	YYSTACK_RELOCATE (nss_expr_yyss);
	YYSTACK_RELOCATE (nss_expr_yyvs);

#  undef YYSTACK_RELOCATE
	if (nss_expr_yyss1 != nss_expr_yyssa)
	  YYSTACK_FREE (nss_expr_yyss1);
      }
# endif
#endif /* no nss_expr_yyoverflow */

      nss_expr_yyssp = nss_expr_yyss + nss_expr_yysize - 1;
      nss_expr_yyvsp = nss_expr_yyvs + nss_expr_yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) nss_expr_yystacksize));

      if (nss_expr_yyss + nss_expr_yystacksize - 1 <= nss_expr_yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", nss_expr_yystate));

  goto nss_expr_yybackup;

/*-----------.
| nss_expr_yybackup.  |
`-----------*/
nss_expr_yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* nss_expr_yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  nss_expr_yyn = nss_expr_yypact[nss_expr_yystate];
  if (nss_expr_yyn == YYPACT_NINF)
    goto nss_expr_yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (nss_expr_yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      nss_expr_yychar = YYLEX;
    }

  if (nss_expr_yychar <= YYEOF)
    {
      nss_expr_yychar = nss_expr_yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      nss_expr_yytoken = YYTRANSLATE (nss_expr_yychar);
      YYDSYMPRINTF ("Next token is", nss_expr_yytoken, &nss_expr_yylval, &nss_expr_yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  nss_expr_yyn += nss_expr_yytoken;
  if (nss_expr_yyn < 0 || YYLAST < nss_expr_yyn || nss_expr_yycheck[nss_expr_yyn] != nss_expr_yytoken)
    goto nss_expr_yydefault;
  nss_expr_yyn = nss_expr_yytable[nss_expr_yyn];
  if (nss_expr_yyn <= 0)
    {
      if (nss_expr_yyn == 0 || nss_expr_yyn == YYTABLE_NINF)
	goto nss_expr_yyerrlab;
      nss_expr_yyn = -nss_expr_yyn;
      goto nss_expr_yyreduce;
    }

  if (nss_expr_yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %s, ", nss_expr_yytname[nss_expr_yytoken]));

  /* Discard the token being shifted unless it is eof.  */
  if (nss_expr_yychar != YYEOF)
    nss_expr_yychar = YYEMPTY;

  *++nss_expr_yyvsp = nss_expr_yylval;


  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (nss_expr_yyerrstatus)
    nss_expr_yyerrstatus--;

  nss_expr_yystate = nss_expr_yyn;
  goto nss_expr_yynewstate;


/*-----------------------------------------------------------.
| nss_expr_yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
nss_expr_yydefault:
  nss_expr_yyn = nss_expr_yydefact[nss_expr_yystate];
  if (nss_expr_yyn == 0)
    goto nss_expr_yyerrlab;
  goto nss_expr_yyreduce;


/*-----------------------------.
| nss_expr_yyreduce -- Do a reduction.  |
`-----------------------------*/
nss_expr_yyreduce:
  /* nss_expr_yyn is the number of a rule to reduce with.  */
  nss_expr_yylen = nss_expr_yyr2[nss_expr_yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  nss_expr_yyval = nss_expr_yyvsp[1-nss_expr_yylen];


  YY_REDUCE_PRINT (nss_expr_yyn);
  switch (nss_expr_yyn)
    {
        case 2:
#line 69 "nss_expr_parse.y"
    { nss_expr_info.expr = nss_expr_yyvsp[0].exVal; }
    break;

  case 3:
#line 72 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_True,  NULL, NULL); }
    break;

  case 4:
#line 73 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_False, NULL, NULL); }
    break;

  case 5:
#line 74 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_Not,   nss_expr_yyvsp[0].exVal,   NULL); }
    break;

  case 6:
#line 75 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_Or,    nss_expr_yyvsp[-2].exVal,   nss_expr_yyvsp[0].exVal);   }
    break;

  case 7:
#line 76 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_And,   nss_expr_yyvsp[-2].exVal,   nss_expr_yyvsp[0].exVal);   }
    break;

  case 8:
#line 77 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_Comp,  nss_expr_yyvsp[0].exVal,   NULL); }
    break;

  case 9:
#line 78 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_yyvsp[-1].exVal; }
    break;

  case 10:
#line 81 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_EQ,  nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); }
    break;

  case 11:
#line 82 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_NE,  nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); }
    break;

  case 12:
#line 83 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_LT,  nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); }
    break;

  case 13:
#line 84 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_LE,  nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); }
    break;

  case 14:
#line 85 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_GT,  nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); }
    break;

  case 15:
#line 86 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_GE,  nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); }
    break;

  case 16:
#line 87 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_IN,  nss_expr_yyvsp[-4].exVal, nss_expr_yyvsp[-1].exVal); }
    break;

  case 17:
#line 88 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_REG, nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); }
    break;

  case 18:
#line 89 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_NRE, nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); }
    break;

  case 19:
#line 92 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_ListElement, nss_expr_yyvsp[0].exVal, NULL); }
    break;

  case 20:
#line 93 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_ListElement, nss_expr_yyvsp[0].exVal, nss_expr_yyvsp[-2].exVal);   }
    break;

  case 21:
#line 96 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_Digit,  nss_expr_yyvsp[0].cpVal, NULL); }
    break;

  case 22:
#line 97 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_String, nss_expr_yyvsp[0].cpVal, NULL); }
    break;

  case 23:
#line 98 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_make(op_Var,    nss_expr_yyvsp[-1].cpVal, NULL); }
    break;

  case 24:
#line 99 "nss_expr_parse.y"
    { nss_expr_yyval.exVal = nss_expr_yyvsp[0].exVal; }
    break;

  case 25:
#line 102 "nss_expr_parse.y"
    { 
                ap_regex_t *regex;
                if ((regex = ap_pregcomp(nss_expr_info.pool, nss_expr_yyvsp[0].cpVal, 
                                         AP_REG_EXTENDED|AP_REG_NOSUB)) == NULL) {
                    nss_expr_error = "Failed to compile regular expression";
                    YYERROR;
                }
                nss_expr_yyval.exVal = nss_expr_make(op_Regex, regex, NULL);
            }
    break;

  case 26:
#line 111 "nss_expr_parse.y"
    {
                ap_regex_t *regex;
                if ((regex = ap_pregcomp(nss_expr_info.pool, nss_expr_yyvsp[0].cpVal, 
                                         AP_REG_EXTENDED|AP_REG_NOSUB|AP_REG_ICASE)) == NULL) {
                    nss_expr_error = "Failed to compile regular expression";
                    YYERROR;
                }
                nss_expr_yyval.exVal = nss_expr_make(op_Regex, regex, NULL);
            }
    break;

  case 27:
#line 122 "nss_expr_parse.y"
    { 
               nss_expr *args = nss_expr_make(op_ListElement, nss_expr_yyvsp[-1].cpVal, NULL);
               nss_expr_yyval.exVal = nss_expr_make(op_Func, "file", args);
            }
    break;


    }

/* Line 1000 of yacc.c.  */
#line 1207 "y.tab.c"

  nss_expr_yyvsp -= nss_expr_yylen;
  nss_expr_yyssp -= nss_expr_yylen;


  YY_STACK_PRINT (nss_expr_yyss, nss_expr_yyssp);

  *++nss_expr_yyvsp = nss_expr_yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  nss_expr_yyn = nss_expr_yyr1[nss_expr_yyn];

  nss_expr_yystate = nss_expr_yypgoto[nss_expr_yyn - YYNTOKENS] + *nss_expr_yyssp;
  if (0 <= nss_expr_yystate && nss_expr_yystate <= YYLAST && nss_expr_yycheck[nss_expr_yystate] == *nss_expr_yyssp)
    nss_expr_yystate = nss_expr_yytable[nss_expr_yystate];
  else
    nss_expr_yystate = nss_expr_yydefgoto[nss_expr_yyn - YYNTOKENS];

  goto nss_expr_yynewstate;


/*------------------------------------.
| nss_expr_yyerrlab -- here on detecting error |
`------------------------------------*/
nss_expr_yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!nss_expr_yyerrstatus)
    {
      ++nss_expr_yynerrs;
#if YYERROR_VERBOSE
      nss_expr_yyn = nss_expr_yypact[nss_expr_yystate];

      if (YYPACT_NINF < nss_expr_yyn && nss_expr_yyn < YYLAST)
	{
	  YYSIZE_T nss_expr_yysize = 0;
	  int nss_expr_yytype = YYTRANSLATE (nss_expr_yychar);
	  const char* nss_expr_yyprefix;
	  char *nss_expr_yymsg;
	  int nss_expr_yyx;

	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  int nss_expr_yyxbegin = nss_expr_yyn < 0 ? -nss_expr_yyn : 0;

	  /* Stay within bounds of both nss_expr_yycheck and nss_expr_yytname.  */
	  int nss_expr_yychecklim = YYLAST - nss_expr_yyn;
	  int nss_expr_yyxend = nss_expr_yychecklim < YYNTOKENS ? nss_expr_yychecklim : YYNTOKENS;
	  int nss_expr_yycount = 0;

	  nss_expr_yyprefix = ", expecting ";
	  for (nss_expr_yyx = nss_expr_yyxbegin; nss_expr_yyx < nss_expr_yyxend; ++nss_expr_yyx)
	    if (nss_expr_yycheck[nss_expr_yyx + nss_expr_yyn] == nss_expr_yyx && nss_expr_yyx != YYTERROR)
	      {
		nss_expr_yysize += nss_expr_yystrlen (nss_expr_yyprefix) + nss_expr_yystrlen (nss_expr_yytname [nss_expr_yyx]);
		nss_expr_yycount += 1;
		if (nss_expr_yycount == 5)
		  {
		    nss_expr_yysize = 0;
		    break;
		  }
	      }
	  nss_expr_yysize += (sizeof ("syntax error, unexpected ")
		     + nss_expr_yystrlen (nss_expr_yytname[nss_expr_yytype]));
	  nss_expr_yymsg = (char *) YYSTACK_ALLOC (nss_expr_yysize);
	  if (nss_expr_yymsg != 0)
	    {
	      char *nss_expr_yyp = nss_expr_yystpcpy (nss_expr_yymsg, "syntax error, unexpected ");
	      nss_expr_yyp = nss_expr_yystpcpy (nss_expr_yyp, nss_expr_yytname[nss_expr_yytype]);

	      if (nss_expr_yycount < 5)
		{
		  nss_expr_yyprefix = ", expecting ";
		  for (nss_expr_yyx = nss_expr_yyxbegin; nss_expr_yyx < nss_expr_yyxend; ++nss_expr_yyx)
		    if (nss_expr_yycheck[nss_expr_yyx + nss_expr_yyn] == nss_expr_yyx && nss_expr_yyx != YYTERROR)
		      {
			nss_expr_yyp = nss_expr_yystpcpy (nss_expr_yyp, nss_expr_yyprefix);
			nss_expr_yyp = nss_expr_yystpcpy (nss_expr_yyp, nss_expr_yytname[nss_expr_yyx]);
			nss_expr_yyprefix = " or ";
		      }
		}
	      nss_expr_yyerror (nss_expr_yymsg);
	      YYSTACK_FREE (nss_expr_yymsg);
	    }
	  else
	    nss_expr_yyerror ("syntax error; also virtual memory exhausted");
	}
      else
#endif /* YYERROR_VERBOSE */
	nss_expr_yyerror ("syntax error");
    }



  if (nss_expr_yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (nss_expr_yychar <= YYEOF)
        {
          /* If at end of input, pop the error token,
	     then the rest of the stack, then return failure.  */
	  if (nss_expr_yychar == YYEOF)
	     for (;;)
	       {
		 YYPOPSTACK;
		 if (nss_expr_yyssp == nss_expr_yyss)
		   YYABORT;
		 YYDSYMPRINTF ("Error: popping", nss_expr_yystos[*nss_expr_yyssp], nss_expr_yyvsp, nss_expr_yylsp);
		 nss_expr_yydestruct (nss_expr_yystos[*nss_expr_yyssp], nss_expr_yyvsp);
	       }
        }
      else
	{
	  YYDSYMPRINTF ("Error: discarding", nss_expr_yytoken, &nss_expr_yylval, &nss_expr_yylloc);
	  nss_expr_yydestruct (nss_expr_yytoken, &nss_expr_yylval);
	  nss_expr_yychar = YYEMPTY;

	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto nss_expr_yyerrlab1;


/*---------------------------------------------------.
| nss_expr_yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
nss_expr_yyerrorlab:

#ifdef __GNUC__
  /* Pacify GCC when the user code never invokes YYERROR and the label
     nss_expr_yyerrorlab therefore never appears in user code.  */
  if (0)
     goto nss_expr_yyerrorlab;
#endif

  nss_expr_yyvsp -= nss_expr_yylen;
  nss_expr_yyssp -= nss_expr_yylen;
  nss_expr_yystate = *nss_expr_yyssp;
  goto nss_expr_yyerrlab1;


/*-------------------------------------------------------------.
| nss_expr_yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
nss_expr_yyerrlab1:
  nss_expr_yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      nss_expr_yyn = nss_expr_yypact[nss_expr_yystate];
      if (nss_expr_yyn != YYPACT_NINF)
	{
	  nss_expr_yyn += YYTERROR;
	  if (0 <= nss_expr_yyn && nss_expr_yyn <= YYLAST && nss_expr_yycheck[nss_expr_yyn] == YYTERROR)
	    {
	      nss_expr_yyn = nss_expr_yytable[nss_expr_yyn];
	      if (0 < nss_expr_yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (nss_expr_yyssp == nss_expr_yyss)
	YYABORT;

      YYDSYMPRINTF ("Error: popping", nss_expr_yystos[*nss_expr_yyssp], nss_expr_yyvsp, nss_expr_yylsp);
      nss_expr_yydestruct (nss_expr_yystos[nss_expr_yystate], nss_expr_yyvsp);
      YYPOPSTACK;
      nss_expr_yystate = *nss_expr_yyssp;
      YY_STACK_PRINT (nss_expr_yyss, nss_expr_yyssp);
    }

  if (nss_expr_yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++nss_expr_yyvsp = nss_expr_yylval;


  nss_expr_yystate = nss_expr_yyn;
  goto nss_expr_yynewstate;


/*-------------------------------------.
| nss_expr_yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
nss_expr_yyacceptlab:
  nss_expr_yyresult = 0;
  goto nss_expr_yyreturn;

/*-----------------------------------.
| nss_expr_yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
nss_expr_yyabortlab:
  nss_expr_yyresult = 1;
  goto nss_expr_yyreturn;

#ifndef nss_expr_yyoverflow
/*----------------------------------------------.
| nss_expr_yyoverflowlab -- parser overflow comes here.  |
`----------------------------------------------*/
nss_expr_yyoverflowlab:
  nss_expr_yyerror ("parser stack overflow");
  nss_expr_yyresult = 2;
  /* Fall through.  */
#endif

nss_expr_yyreturn:
#ifndef nss_expr_yyoverflow
  if (nss_expr_yyss != nss_expr_yyssa)
    YYSTACK_FREE (nss_expr_yyss);
#endif
  return nss_expr_yyresult;
}


#line 128 "nss_expr_parse.y"


int nss_expr_yyerror(char *s)
{
    nss_expr_error = s;
    return 2;
}


