
/*  A Bison parser, made from nss_expr_parse.y
    by GNU Bison version 1.28  */

#define YYBISON 1  /* Identify Bison output.  */

#define	T_TRUE	257
#define	T_FALSE	258
#define	T_DIGIT	259
#define	T_ID	260
#define	T_STRING	261
#define	T_REGEX	262
#define	T_REGEX_I	263
#define	T_FUNC_FILE	264
#define	T_OP_EQ	265
#define	T_OP_NE	266
#define	T_OP_LT	267
#define	T_OP_LE	268
#define	T_OP_GT	269
#define	T_OP_GE	270
#define	T_OP_REG	271
#define	T_OP_NRE	272
#define	T_OP_IN	273
#define	T_OP_OR	274
#define	T_OP_AND	275
#define	T_OP_NOT	276

#line 22 "nss_expr_parse.y"

#include "mod_nss.h"

#line 26 "nss_expr_parse.y"
typedef union {
    char     *cpVal;
    nss_expr *exVal;
} YYSTYPE;
#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		53
#define	YYFLAG		-32768
#define	YYNTBASE	29

#define YYTRANSLATE(x) ((unsigned)(x) <= 276 ? nss_expr_yytranslate[x] : 36)

static const char nss_expr_yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,    28,     2,     2,    23,
    24,     2,     2,    27,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,    25,     2,    26,     2,     2,     2,     2,     2,
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
     2,     2,     2,     2,     2,     1,     3,     4,     5,     6,
     7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
    17,    18,    19,    20,    21,    22
};

#if YYDEBUG != 0
static const short nss_expr_yyprhs[] = {     0,
     0,     2,     4,     6,     9,    13,    17,    19,    23,    27,
    31,    35,    39,    43,    47,    53,    57,    61,    63,    67,
    69,    71,    76,    78,    80,    82
};

static const short nss_expr_yyrhs[] = {    30,
     0,     3,     0,     4,     0,    22,    30,     0,    30,    20,
    30,     0,    30,    21,    30,     0,    31,     0,    23,    30,
    24,     0,    33,    11,    33,     0,    33,    12,    33,     0,
    33,    13,    33,     0,    33,    14,    33,     0,    33,    15,
    33,     0,    33,    16,    33,     0,    33,    19,    25,    32,
    26,     0,    33,    17,    34,     0,    33,    18,    34,     0,
    33,     0,    32,    27,    33,     0,     5,     0,     7,     0,
    28,    25,     6,    26,     0,    35,     0,     8,     0,     9,
     0,    10,    23,     7,    24,     0
};

#endif

#if YYDEBUG != 0
static const short nss_expr_yyrline[] = { 0,
    69,    72,    73,    74,    75,    76,    77,    78,    81,    82,
    83,    84,    85,    86,    87,    88,    89,    92,    93,    96,
    97,    98,    99,   102,   111,   122
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const nss_expr_yytname[] = {   "$","error","$undefined.","T_TRUE",
"T_FALSE","T_DIGIT","T_ID","T_STRING","T_REGEX","T_REGEX_I","T_FUNC_FILE","T_OP_EQ",
"T_OP_NE","T_OP_LT","T_OP_LE","T_OP_GT","T_OP_GE","T_OP_REG","T_OP_NRE","T_OP_IN",
"T_OP_OR","T_OP_AND","T_OP_NOT","'('","')'","'{'","'}'","','","'%'","root","expr",
"comparison","words","word","regex","funccall", NULL
};
#endif

static const short nss_expr_yyr1[] = {     0,
    29,    30,    30,    30,    30,    30,    30,    30,    31,    31,
    31,    31,    31,    31,    31,    31,    31,    32,    32,    33,
    33,    33,    33,    34,    34,    35
};

static const short nss_expr_yyr2[] = {     0,
     1,     1,     1,     2,     3,     3,     1,     3,     3,     3,
     3,     3,     3,     3,     5,     3,     3,     1,     3,     1,
     1,     4,     1,     1,     1,     4
};

static const short nss_expr_yydefact[] = {     0,
     2,     3,    20,    21,     0,     0,     0,     0,     1,     7,
     0,    23,     0,     4,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     8,     0,
     5,     6,     9,    10,    11,    12,    13,    14,    24,    25,
    16,    17,     0,    26,    22,     0,    18,    15,     0,    19,
     0,     0,     0
};

static const short nss_expr_yydefgoto[] = {    51,
     9,    10,    46,    11,    41,    12
};

static const short nss_expr_yypact[] = {     3,
-32768,-32768,-32768,-32768,   -11,     3,     3,   -10,     0,-32768,
    22,-32768,    16,-32768,    -2,    23,     3,     3,     4,     4,
     4,     4,     4,     4,    34,    34,    21,    24,-32768,    25,
    26,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,     4,-32768,-32768,    18,-32768,-32768,     4,-32768,
    49,    50,-32768
};

static const short nss_expr_yypgoto[] = {-32768,
    10,-32768,-32768,   -19,    27,-32768
};


#define	YYLAST		53


static const short nss_expr_yytable[] = {    33,
    34,    35,    36,    37,    38,     1,     2,     3,     3,     4,
     4,    13,     5,     5,    16,    14,    15,    17,    18,    17,
    18,    29,    28,    47,     6,     7,    31,    32,    30,    50,
     8,     8,    19,    20,    21,    22,    23,    24,    25,    26,
    27,    39,    40,    48,    49,    43,    18,    44,    52,    53,
    45,     0,    42
};

static const short nss_expr_yycheck[] = {    19,
    20,    21,    22,    23,    24,     3,     4,     5,     5,     7,
     7,    23,    10,    10,    25,     6,     7,    20,    21,    20,
    21,    24,     7,    43,    22,    23,    17,    18,     6,    49,
    28,    28,    11,    12,    13,    14,    15,    16,    17,    18,
    19,     8,     9,    26,    27,    25,    21,    24,     0,     0,
    26,    -1,    26
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/lib/bison.simple"
/* This file comes from bison-1.28.  */

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990 Free Software Foundation, Inc.

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

/* This is the parser code that is written into each bison parser
  when the %semantic_parser declaration is not specified in the grammar.
  It was written by Richard Stallman by simplifying the hairy parser
  used when %semantic_parser is specified.  */

#ifndef YYSTACK_USE_ALLOCA
#ifdef alloca
#define YYSTACK_USE_ALLOCA
#else /* alloca not defined */
#ifdef __GNUC__
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#else /* not GNU C.  */
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__) || defined (__sparc) || defined (__sgi) || (defined (__sun) && defined (__i386))
#define YYSTACK_USE_ALLOCA
#include <alloca.h>
#else /* not sparc */
/* We think this test detects Watcom and Microsoft C.  */
/* This used to test MSDOS, but that is a bad idea
   since that symbol is in the user namespace.  */
#if (defined (_MSDOS) || defined (_MSDOS_)) && !defined (__TURBOC__)
#if 0 /* No need for malloc.h, which pollutes the namespace;
	 instead, just don't use alloca.  */
#include <malloc.h>
#endif
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
/* I don't know what this was needed for, but it pollutes the namespace.
   So I turned it off.   rms, 2 May 1997.  */
/* #include <malloc.h>  */
 #pragma alloca
#define YYSTACK_USE_ALLOCA
#else /* not MSDOS, or __TURBOC__, or _AIX */
#if 0
#ifdef __hpux /* haible@ilog.fr says this works for HPUX 9.05 and up,
		 and on HPUX 10.  Eventually we can turn this on.  */
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#endif /* __hpux */
#endif
#endif /* not _AIX */
#endif /* not MSDOS, or __TURBOC__ */
#endif /* not sparc */
#endif /* not GNU C */
#endif /* alloca not defined */
#endif /* YYSTACK_USE_ALLOCA not defined */

#ifdef YYSTACK_USE_ALLOCA
#define YYSTACK_ALLOC alloca
#else
#define YYSTACK_ALLOC malloc
#endif

/* Note: there must be only one dollar sign in this file.
   It is replaced by the list of actions, each action
   as one case of the switch.  */

#define nss_expr_yyerrok		(nss_expr_yyerrstatus = 0)
#define nss_expr_yyclearin	(nss_expr_yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	goto nss_expr_yyacceptlab
#define YYABORT 	goto nss_expr_yyabortlab
#define YYERROR		goto nss_expr_yyerrlab1
/* Like YYERROR except do call nss_expr_yyerror.
   This remains here temporarily to ease the
   transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto nss_expr_yyerrlab
#define YYRECOVERING()  (!!nss_expr_yyerrstatus)
#define YYBACKUP(token, value) \
do								\
  if (nss_expr_yychar == YYEMPTY && nss_expr_yylen == 1)				\
    { nss_expr_yychar = (token), nss_expr_yylval = (value);			\
      nss_expr_yychar1 = YYTRANSLATE (nss_expr_yychar);				\
      YYPOPSTACK;						\
      goto nss_expr_yybackup;						\
    }								\
  else								\
    { nss_expr_yyerror ("syntax error: cannot back up"); YYERROR; }	\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

#ifndef YYPURE
#define YYLEX		nss_expr_yylex()
#endif

#ifdef YYPURE
#ifdef YYLSP_NEEDED
#ifdef YYLEX_PARAM
#define YYLEX		nss_expr_yylex(&nss_expr_yylval, &nss_expr_yylloc, YYLEX_PARAM)
#else
#define YYLEX		nss_expr_yylex(&nss_expr_yylval, &nss_expr_yylloc)
#endif
#else /* not YYLSP_NEEDED */
#ifdef YYLEX_PARAM
#define YYLEX		nss_expr_yylex(&nss_expr_yylval, YYLEX_PARAM)
#else
#define YYLEX		nss_expr_yylex(&nss_expr_yylval)
#endif
#endif /* not YYLSP_NEEDED */
#endif

/* If nonreentrant, generate the variables here */

#ifndef YYPURE

int	nss_expr_yychar;			/*  the lookahead symbol		*/
YYSTYPE	nss_expr_yylval;			/*  the semantic value of the		*/
				/*  lookahead symbol			*/

#ifdef YYLSP_NEEDED
YYLTYPE nss_expr_yylloc;			/*  location data for the lookahead	*/
				/*  symbol				*/
#endif

int nss_expr_yynerrs;			/*  number of parse errors so far       */
#endif  /* not YYPURE */

#if YYDEBUG != 0
int nss_expr_yydebug;			/*  nonzero means print parse trace	*/
/* Since this is uninitialized, it does not stop multiple parsers
   from coexisting.  */
#endif

/*  YYINITDEPTH indicates the initial size of the parser's stacks	*/

#ifndef	YYINITDEPTH
#define YYINITDEPTH 200
#endif

/*  YYMAXDEPTH is the maximum size the stacks can grow to
    (effective only if the built-in stack extension method is used).  */

#if YYMAXDEPTH == 0
#undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 10000
#endif

/* Define __nss_expr_yy_memcpy.  Note that the size argument
   should be passed with type unsigned int, because that is what the non-GCC
   definitions require.  With GCC, __builtin_memcpy takes an arg
   of type size_t, but it can handle unsigned int.  */

#if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#define __nss_expr_yy_memcpy(TO,FROM,COUNT)	__builtin_memcpy(TO,FROM,COUNT)
#else				/* not GNU C or C++ */
#ifndef __cplusplus

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__nss_expr_yy_memcpy (to, from, count)
     char *to;
     char *from;
     unsigned int count;
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#else /* __cplusplus */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__nss_expr_yy_memcpy (char *to, char *from, unsigned int count)
{
  register char *t = to;
  register char *f = from;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#endif
#endif

#line 217 "/usr/lib/bison.simple"

/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into nss_expr_yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
#ifdef __cplusplus
#define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else /* not __cplusplus */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
#endif /* not __cplusplus */
#else /* not YYPARSE_PARAM */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif /* not YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
#ifdef YYPARSE_PARAM
int nss_expr_yyparse (void *);
#else
int nss_expr_yyparse (void);
#endif
#endif

int
nss_expr_yyparse(YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  register int nss_expr_yystate;
  register int nss_expr_yyn;
  register short *nss_expr_yyssp;
  register YYSTYPE *nss_expr_yyvsp;
  int nss_expr_yyerrstatus;	/*  number of tokens to shift before error messages enabled */
  int nss_expr_yychar1 = 0;		/*  lookahead token as an internal (translated) token number */

  short	nss_expr_yyssa[YYINITDEPTH];	/*  the state stack			*/
  YYSTYPE nss_expr_yyvsa[YYINITDEPTH];	/*  the semantic value stack		*/

  short *nss_expr_yyss = nss_expr_yyssa;		/*  refer to the stacks thru separate pointers */
  YYSTYPE *nss_expr_yyvs = nss_expr_yyvsa;	/*  to allow nss_expr_yyoverflow to reallocate them elsewhere */

#ifdef YYLSP_NEEDED
  YYLTYPE nss_expr_yylsa[YYINITDEPTH];	/*  the location stack			*/
  YYLTYPE *nss_expr_yyls = nss_expr_yylsa;
  YYLTYPE *nss_expr_yylsp;

#define YYPOPSTACK   (nss_expr_yyvsp--, nss_expr_yyssp--, nss_expr_yylsp--)
#else
#define YYPOPSTACK   (nss_expr_yyvsp--, nss_expr_yyssp--)
#endif

  int nss_expr_yystacksize = YYINITDEPTH;
  int nss_expr_yyfree_stacks = 0;

#ifdef YYPURE
  int nss_expr_yychar;
  YYSTYPE nss_expr_yylval;
  int nss_expr_yynerrs;
#ifdef YYLSP_NEEDED
  YYLTYPE nss_expr_yylloc;
#endif
#endif

  YYSTYPE nss_expr_yyval;		/*  the variable used to return		*/
				/*  semantic values from the action	*/
				/*  routines				*/

  int nss_expr_yylen;

#if YYDEBUG != 0
  if (nss_expr_yydebug)
    fprintf(stderr, "Starting parse\n");
#endif

  nss_expr_yystate = 0;
  nss_expr_yyerrstatus = 0;
  nss_expr_yynerrs = 0;
  nss_expr_yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  nss_expr_yyssp = nss_expr_yyss - 1;
  nss_expr_yyvsp = nss_expr_yyvs;
#ifdef YYLSP_NEEDED
  nss_expr_yylsp = nss_expr_yyls;
#endif

/* Push a new state, which is found in  nss_expr_yystate  .  */
/* In all cases, when you get here, the value and location stacks
   have just been pushed. so pushing a state here evens the stacks.  */
nss_expr_yynewstate:

  *++nss_expr_yyssp = nss_expr_yystate;

  if (nss_expr_yyssp >= nss_expr_yyss + nss_expr_yystacksize - 1)
    {
      /* Give user a chance to reallocate the stack */
      /* Use copies of these so that the &'s don't force the real ones into memory. */
      YYSTYPE *nss_expr_yyvs1 = nss_expr_yyvs;
      short *nss_expr_yyss1 = nss_expr_yyss;
#ifdef YYLSP_NEEDED
      YYLTYPE *nss_expr_yyls1 = nss_expr_yyls;
#endif

      /* Get the current used size of the three stacks, in elements.  */
      int size = nss_expr_yyssp - nss_expr_yyss + 1;

#ifdef nss_expr_yyoverflow
      /* Each stack pointer address is followed by the size of
	 the data in use in that stack, in bytes.  */
#ifdef YYLSP_NEEDED
      /* This used to be a conditional around just the two extra args,
	 but that might be undefined if nss_expr_yyoverflow is a macro.  */
      nss_expr_yyoverflow("parser stack overflow",
		 &nss_expr_yyss1, size * sizeof (*nss_expr_yyssp),
		 &nss_expr_yyvs1, size * sizeof (*nss_expr_yyvsp),
		 &nss_expr_yyls1, size * sizeof (*nss_expr_yylsp),
		 &nss_expr_yystacksize);
#else
      nss_expr_yyoverflow("parser stack overflow",
		 &nss_expr_yyss1, size * sizeof (*nss_expr_yyssp),
		 &nss_expr_yyvs1, size * sizeof (*nss_expr_yyvsp),
		 &nss_expr_yystacksize);
#endif

      nss_expr_yyss = nss_expr_yyss1; nss_expr_yyvs = nss_expr_yyvs1;
#ifdef YYLSP_NEEDED
      nss_expr_yyls = nss_expr_yyls1;
#endif
#else /* no nss_expr_yyoverflow */
      /* Extend the stack our own way.  */
      if (nss_expr_yystacksize >= YYMAXDEPTH)
	{
	  nss_expr_yyerror("parser stack overflow");
	  if (nss_expr_yyfree_stacks)
	    {
	      free (nss_expr_yyss);
	      free (nss_expr_yyvs);
#ifdef YYLSP_NEEDED
	      free (nss_expr_yyls);
#endif
	    }
	  return 2;
	}
      nss_expr_yystacksize *= 2;
      if (nss_expr_yystacksize > YYMAXDEPTH)
	nss_expr_yystacksize = YYMAXDEPTH;
#ifndef YYSTACK_USE_ALLOCA
      nss_expr_yyfree_stacks = 1;
#endif
      nss_expr_yyss = (short *) YYSTACK_ALLOC (nss_expr_yystacksize * sizeof (*nss_expr_yyssp));
      __nss_expr_yy_memcpy ((char *)nss_expr_yyss, (char *)nss_expr_yyss1,
		   size * (unsigned int) sizeof (*nss_expr_yyssp));
      nss_expr_yyvs = (YYSTYPE *) YYSTACK_ALLOC (nss_expr_yystacksize * sizeof (*nss_expr_yyvsp));
      __nss_expr_yy_memcpy ((char *)nss_expr_yyvs, (char *)nss_expr_yyvs1,
		   size * (unsigned int) sizeof (*nss_expr_yyvsp));
#ifdef YYLSP_NEEDED
      nss_expr_yyls = (YYLTYPE *) YYSTACK_ALLOC (nss_expr_yystacksize * sizeof (*nss_expr_yylsp));
      __nss_expr_yy_memcpy ((char *)nss_expr_yyls, (char *)nss_expr_yyls1,
		   size * (unsigned int) sizeof (*nss_expr_yylsp));
#endif
#endif /* no nss_expr_yyoverflow */

      nss_expr_yyssp = nss_expr_yyss + size - 1;
      nss_expr_yyvsp = nss_expr_yyvs + size - 1;
#ifdef YYLSP_NEEDED
      nss_expr_yylsp = nss_expr_yyls + size - 1;
#endif

#if YYDEBUG != 0
      if (nss_expr_yydebug)
	fprintf(stderr, "Stack size increased to %d\n", nss_expr_yystacksize);
#endif

      if (nss_expr_yyssp >= nss_expr_yyss + nss_expr_yystacksize - 1)
	YYABORT;
    }

#if YYDEBUG != 0
  if (nss_expr_yydebug)
    fprintf(stderr, "Entering state %d\n", nss_expr_yystate);
#endif

  goto nss_expr_yybackup;
 nss_expr_yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* nss_expr_yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  nss_expr_yyn = nss_expr_yypact[nss_expr_yystate];
  if (nss_expr_yyn == YYFLAG)
    goto nss_expr_yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* nss_expr_yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (nss_expr_yychar == YYEMPTY)
    {
#if YYDEBUG != 0
      if (nss_expr_yydebug)
	fprintf(stderr, "Reading a token: ");
#endif
      nss_expr_yychar = YYLEX;
    }

  /* Convert token to internal form (in nss_expr_yychar1) for indexing tables with */

  if (nss_expr_yychar <= 0)		/* This means end of input. */
    {
      nss_expr_yychar1 = 0;
      nss_expr_yychar = YYEOF;		/* Don't call YYLEX any more */

#if YYDEBUG != 0
      if (nss_expr_yydebug)
	fprintf(stderr, "Now at end of input.\n");
#endif
    }
  else
    {
      nss_expr_yychar1 = YYTRANSLATE(nss_expr_yychar);

#if YYDEBUG != 0
      if (nss_expr_yydebug)
	{
	  fprintf (stderr, "Next token is %d (%s", nss_expr_yychar, nss_expr_yytname[nss_expr_yychar1]);
	  /* Give the individual parser a way to print the precise meaning
	     of a token, for further debugging info.  */
#ifdef YYPRINT
	  YYPRINT (stderr, nss_expr_yychar, nss_expr_yylval);
#endif
	  fprintf (stderr, ")\n");
	}
#endif
    }

  nss_expr_yyn += nss_expr_yychar1;
  if (nss_expr_yyn < 0 || nss_expr_yyn > YYLAST || nss_expr_yycheck[nss_expr_yyn] != nss_expr_yychar1)
    goto nss_expr_yydefault;

  nss_expr_yyn = nss_expr_yytable[nss_expr_yyn];

  /* nss_expr_yyn is what to do for this token type in this state.
     Negative => reduce, -nss_expr_yyn is rule number.
     Positive => shift, nss_expr_yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (nss_expr_yyn < 0)
    {
      if (nss_expr_yyn == YYFLAG)
	goto nss_expr_yyerrlab;
      nss_expr_yyn = -nss_expr_yyn;
      goto nss_expr_yyreduce;
    }
  else if (nss_expr_yyn == 0)
    goto nss_expr_yyerrlab;

  if (nss_expr_yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */

#if YYDEBUG != 0
  if (nss_expr_yydebug)
    fprintf(stderr, "Shifting token %d (%s), ", nss_expr_yychar, nss_expr_yytname[nss_expr_yychar1]);
#endif

  /* Discard the token being shifted unless it is eof.  */
  if (nss_expr_yychar != YYEOF)
    nss_expr_yychar = YYEMPTY;

  *++nss_expr_yyvsp = nss_expr_yylval;
#ifdef YYLSP_NEEDED
  *++nss_expr_yylsp = nss_expr_yylloc;
#endif

  /* count tokens shifted since error; after three, turn off error status.  */
  if (nss_expr_yyerrstatus) nss_expr_yyerrstatus--;

  nss_expr_yystate = nss_expr_yyn;
  goto nss_expr_yynewstate;

/* Do the default action for the current state.  */
nss_expr_yydefault:

  nss_expr_yyn = nss_expr_yydefact[nss_expr_yystate];
  if (nss_expr_yyn == 0)
    goto nss_expr_yyerrlab;

/* Do a reduction.  nss_expr_yyn is the number of a rule to reduce with.  */
nss_expr_yyreduce:
  nss_expr_yylen = nss_expr_yyr2[nss_expr_yyn];
  if (nss_expr_yylen > 0)
    nss_expr_yyval = nss_expr_yyvsp[1-nss_expr_yylen]; /* implement default value of the action */

#if YYDEBUG != 0
  if (nss_expr_yydebug)
    {
      int i;

      fprintf (stderr, "Reducing via rule %d (line %d), ",
	       nss_expr_yyn, nss_expr_yyrline[nss_expr_yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (i = nss_expr_yyprhs[nss_expr_yyn]; nss_expr_yyrhs[i] > 0; i++)
	fprintf (stderr, "%s ", nss_expr_yytname[nss_expr_yyrhs[i]]);
      fprintf (stderr, " -> %s\n", nss_expr_yytname[nss_expr_yyr1[nss_expr_yyn]]);
    }
#endif


  switch (nss_expr_yyn) {

case 1:
#line 69 "nss_expr_parse.y"
{ nss_expr_info.expr = nss_expr_yyvsp[0].exVal; ;
    break;}
case 2:
#line 72 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_True,  NULL, NULL); ;
    break;}
case 3:
#line 73 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_False, NULL, NULL); ;
    break;}
case 4:
#line 74 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_Not,   nss_expr_yyvsp[0].exVal,   NULL); ;
    break;}
case 5:
#line 75 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_Or,    nss_expr_yyvsp[-2].exVal,   nss_expr_yyvsp[0].exVal);   ;
    break;}
case 6:
#line 76 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_And,   nss_expr_yyvsp[-2].exVal,   nss_expr_yyvsp[0].exVal);   ;
    break;}
case 7:
#line 77 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_Comp,  nss_expr_yyvsp[0].exVal,   NULL); ;
    break;}
case 8:
#line 78 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_yyvsp[-1].exVal; ;
    break;}
case 9:
#line 81 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_EQ,  nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); ;
    break;}
case 10:
#line 82 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_NE,  nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); ;
    break;}
case 11:
#line 83 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_LT,  nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); ;
    break;}
case 12:
#line 84 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_LE,  nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); ;
    break;}
case 13:
#line 85 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_GT,  nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); ;
    break;}
case 14:
#line 86 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_GE,  nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); ;
    break;}
case 15:
#line 87 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_IN,  nss_expr_yyvsp[-4].exVal, nss_expr_yyvsp[-1].exVal); ;
    break;}
case 16:
#line 88 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_REG, nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); ;
    break;}
case 17:
#line 89 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_NRE, nss_expr_yyvsp[-2].exVal, nss_expr_yyvsp[0].exVal); ;
    break;}
case 18:
#line 92 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_ListElement, nss_expr_yyvsp[0].exVal, NULL); ;
    break;}
case 19:
#line 93 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_ListElement, nss_expr_yyvsp[0].exVal, nss_expr_yyvsp[-2].exVal);   ;
    break;}
case 20:
#line 96 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_Digit,  nss_expr_yyvsp[0].cpVal, NULL); ;
    break;}
case 21:
#line 97 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_String, nss_expr_yyvsp[0].cpVal, NULL); ;
    break;}
case 22:
#line 98 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_make(op_Var,    nss_expr_yyvsp[-1].cpVal, NULL); ;
    break;}
case 23:
#line 99 "nss_expr_parse.y"
{ nss_expr_yyval.exVal = nss_expr_yyvsp[0].exVal; ;
    break;}
case 24:
#line 102 "nss_expr_parse.y"
{ 
                regex_t *regex;
                if ((regex = ap_pregcomp(nss_expr_info.pool, nss_expr_yyvsp[0].cpVal, 
                                         REG_EXTENDED|REG_NOSUB)) == NULL) {
                    nss_expr_error = "Failed to compile regular expression";
                    YYERROR;
                }
                nss_expr_yyval.exVal = nss_expr_make(op_Regex, regex, NULL);
            ;
    break;}
case 25:
#line 111 "nss_expr_parse.y"
{
                regex_t *regex;
                if ((regex = ap_pregcomp(nss_expr_info.pool, nss_expr_yyvsp[0].cpVal, 
                                         REG_EXTENDED|REG_NOSUB|REG_ICASE)) == NULL) {
                    nss_expr_error = "Failed to compile regular expression";
                    YYERROR;
                }
                nss_expr_yyval.exVal = nss_expr_make(op_Regex, regex, NULL);
            ;
    break;}
case 26:
#line 122 "nss_expr_parse.y"
{ 
               nss_expr *args = nss_expr_make(op_ListElement, nss_expr_yyvsp[-1].cpVal, NULL);
               nss_expr_yyval.exVal = nss_expr_make(op_Func, "file", args);
            ;
    break;}
}
   /* the action file gets copied in in place of this dollarsign */
#line 543 "/usr/lib/bison.simple"

  nss_expr_yyvsp -= nss_expr_yylen;
  nss_expr_yyssp -= nss_expr_yylen;
#ifdef YYLSP_NEEDED
  nss_expr_yylsp -= nss_expr_yylen;
#endif

#if YYDEBUG != 0
  if (nss_expr_yydebug)
    {
      short *ssp1 = nss_expr_yyss - 1;
      fprintf (stderr, "state stack now");
      while (ssp1 != nss_expr_yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

  *++nss_expr_yyvsp = nss_expr_yyval;

#ifdef YYLSP_NEEDED
  nss_expr_yylsp++;
  if (nss_expr_yylen == 0)
    {
      nss_expr_yylsp->first_line = nss_expr_yylloc.first_line;
      nss_expr_yylsp->first_column = nss_expr_yylloc.first_column;
      nss_expr_yylsp->last_line = (nss_expr_yylsp-1)->last_line;
      nss_expr_yylsp->last_column = (nss_expr_yylsp-1)->last_column;
      nss_expr_yylsp->text = 0;
    }
  else
    {
      nss_expr_yylsp->last_line = (nss_expr_yylsp+nss_expr_yylen-1)->last_line;
      nss_expr_yylsp->last_column = (nss_expr_yylsp+nss_expr_yylen-1)->last_column;
    }
#endif

  /* Now "shift" the result of the reduction.
     Determine what state that goes to,
     based on the state we popped back to
     and the rule number reduced by.  */

  nss_expr_yyn = nss_expr_yyr1[nss_expr_yyn];

  nss_expr_yystate = nss_expr_yypgoto[nss_expr_yyn - YYNTBASE] + *nss_expr_yyssp;
  if (nss_expr_yystate >= 0 && nss_expr_yystate <= YYLAST && nss_expr_yycheck[nss_expr_yystate] == *nss_expr_yyssp)
    nss_expr_yystate = nss_expr_yytable[nss_expr_yystate];
  else
    nss_expr_yystate = nss_expr_yydefgoto[nss_expr_yyn - YYNTBASE];

  goto nss_expr_yynewstate;

nss_expr_yyerrlab:   /* here on detecting error */

  if (! nss_expr_yyerrstatus)
    /* If not already recovering from an error, report this error.  */
    {
      ++nss_expr_yynerrs;

#ifdef YYERROR_VERBOSE
      nss_expr_yyn = nss_expr_yypact[nss_expr_yystate];

      if (nss_expr_yyn > YYFLAG && nss_expr_yyn < YYLAST)
	{
	  int size = 0;
	  char *msg;
	  int x, count;

	  count = 0;
	  /* Start X at -nss_expr_yyn if nec to avoid negative indexes in nss_expr_yycheck.  */
	  for (x = (nss_expr_yyn < 0 ? -nss_expr_yyn : 0);
	       x < (sizeof(nss_expr_yytname) / sizeof(char *)); x++)
	    if (nss_expr_yycheck[x + nss_expr_yyn] == x)
	      size += strlen(nss_expr_yytname[x]) + 15, count++;
	  msg = (char *) malloc(size + 15);
	  if (msg != 0)
	    {
	      strcpy(msg, "parse error");

	      if (count < 5)
		{
		  count = 0;
		  for (x = (nss_expr_yyn < 0 ? -nss_expr_yyn : 0);
		       x < (sizeof(nss_expr_yytname) / sizeof(char *)); x++)
		    if (nss_expr_yycheck[x + nss_expr_yyn] == x)
		      {
			strcat(msg, count == 0 ? ", expecting `" : " or `");
			strcat(msg, nss_expr_yytname[x]);
			strcat(msg, "'");
			count++;
		      }
		}
	      nss_expr_yyerror(msg);
	      free(msg);
	    }
	  else
	    nss_expr_yyerror ("parse error; also virtual memory exceeded");
	}
      else
#endif /* YYERROR_VERBOSE */
	nss_expr_yyerror("parse error");
    }

  goto nss_expr_yyerrlab1;
nss_expr_yyerrlab1:   /* here on error raised explicitly by an action */

  if (nss_expr_yyerrstatus == 3)
    {
      /* if just tried and failed to reuse lookahead token after an error, discard it.  */

      /* return failure if at end of input */
      if (nss_expr_yychar == YYEOF)
	YYABORT;

#if YYDEBUG != 0
      if (nss_expr_yydebug)
	fprintf(stderr, "Discarding token %d (%s).\n", nss_expr_yychar, nss_expr_yytname[nss_expr_yychar1]);
#endif

      nss_expr_yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token
     after shifting the error token.  */

  nss_expr_yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto nss_expr_yyerrhandle;

nss_expr_yyerrdefault:  /* current state does not do anything special for the error token. */

#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */
  nss_expr_yyn = nss_expr_yydefact[nss_expr_yystate];  /* If its default is to accept any token, ok.  Otherwise pop it.*/
  if (nss_expr_yyn) goto nss_expr_yydefault;
#endif

nss_expr_yyerrpop:   /* pop the current state because it cannot handle the error token */

  if (nss_expr_yyssp == nss_expr_yyss) YYABORT;
  nss_expr_yyvsp--;
  nss_expr_yystate = *--nss_expr_yyssp;
#ifdef YYLSP_NEEDED
  nss_expr_yylsp--;
#endif

#if YYDEBUG != 0
  if (nss_expr_yydebug)
    {
      short *ssp1 = nss_expr_yyss - 1;
      fprintf (stderr, "Error: state stack now");
      while (ssp1 != nss_expr_yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

nss_expr_yyerrhandle:

  nss_expr_yyn = nss_expr_yypact[nss_expr_yystate];
  if (nss_expr_yyn == YYFLAG)
    goto nss_expr_yyerrdefault;

  nss_expr_yyn += YYTERROR;
  if (nss_expr_yyn < 0 || nss_expr_yyn > YYLAST || nss_expr_yycheck[nss_expr_yyn] != YYTERROR)
    goto nss_expr_yyerrdefault;

  nss_expr_yyn = nss_expr_yytable[nss_expr_yyn];
  if (nss_expr_yyn < 0)
    {
      if (nss_expr_yyn == YYFLAG)
	goto nss_expr_yyerrpop;
      nss_expr_yyn = -nss_expr_yyn;
      goto nss_expr_yyreduce;
    }
  else if (nss_expr_yyn == 0)
    goto nss_expr_yyerrpop;

  if (nss_expr_yyn == YYFINAL)
    YYACCEPT;

#if YYDEBUG != 0
  if (nss_expr_yydebug)
    fprintf(stderr, "Shifting error token, ");
#endif

  *++nss_expr_yyvsp = nss_expr_yylval;
#ifdef YYLSP_NEEDED
  *++nss_expr_yylsp = nss_expr_yylloc;
#endif

  nss_expr_yystate = nss_expr_yyn;
  goto nss_expr_yynewstate;

 nss_expr_yyacceptlab:
  /* YYACCEPT comes here.  */
  if (nss_expr_yyfree_stacks)
    {
      free (nss_expr_yyss);
      free (nss_expr_yyvs);
#ifdef YYLSP_NEEDED
      free (nss_expr_yyls);
#endif
    }
  return 0;

 nss_expr_yyabortlab:
  /* YYABORT comes here.  */
  if (nss_expr_yyfree_stacks)
    {
      free (nss_expr_yyss);
      free (nss_expr_yyvs);
#ifdef YYLSP_NEEDED
      free (nss_expr_yyls);
#endif
    }
  return 1;
}
#line 128 "nss_expr_parse.y"


int nss_expr_yyerror(char *s)
{
    nss_expr_error = s;
    return 2;
}

