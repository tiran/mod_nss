# Required initializer
AC_INIT([mod_nss],[1.0.14])

m4_include([acinclude.m4])

# Automake initialization
AM_INIT_AUTOMAKE

# Add a test for a compiler.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_LIBTOOL
AC_CONFIG_HEADERS([config.h])

# Check for header files
AC_HEADER_STDC
AC_CHECK_HEADERS( \
unistd.h
)

# Check for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Find lex and yacc (or flex and bison)
AC_PROG_YACC
AC_PROG_LEX
AC_DECL_YYTEXT

AC_MSG_CHECKING(for ECC)
AC_ARG_ENABLE(ecc,
  [  --enable-ecc          enable Elliptical Curve Cyptography (default=no)],
  ecc=$enableval, ecc=no)
if test $ecc = yes; then
   AC_MSG_RESULT(yes)
   extra_cppflags="$extra_cppflags -DNSS_ENABLE_ECC"
else
   AC_MSG_RESULT(no)
fi
#AM_CONDITIONAL(ECC, test x$ecc = xyes)

AC_CHECKING(for apr-config)
# check for --with-apr-config
AC_MSG_CHECKING(for --with-apr-config)
AC_ARG_WITH(apr-config, [  --with-apr-config       Use apr-config to determine the APR directory],
[
  if test -x "$withval"
  then
    AC_MSG_RESULT([using $withval])
    APR_CONFIG=$withval
  fi
],
AC_MSG_RESULT(no))

if test -z "$APR_CONFIG" ; then
  AC_MSG_CHECKING(for apr-1-config and apr-config)
  AC_PATH_PROGS(APR_CONFIG, apr-1-config apr-config, NO_APR_CONFIG, [$PATH:/usr/local/apache/sbin:/usr/sbin])
fi

if test -n "$APR_CONFIG"; then
  AC_MSG_RESULT([using $APR_CONFIG. Use --with-apr-config to specify another.])
  apr_inc=`$APR_CONFIG --includes`
else
  AC_MSG_ERROR([neither apr-config nor apr-1-config were not found. use --with-apr-config to specify it.])
fi

AC_CHECKING(for apxs)

# check for --with-apxs
AC_MSG_CHECKING(for --with-apxs)
AC_ARG_WITH(apxs, [  --with-apxs=PATH        Path to apxs],
[
  if test -x "$withval"
  then
    AC_MSG_RESULT([using $withval])
    APXS=$withval
  else
    echo
    AC_MSG_ERROR([$withval not found or not executable])
  fi
],
AC_MSG_RESULT(no))

# if no apxs found yet, check /usr/local/apache/sbin
# since it's the default Apache location
if test -z "$APXS"; then
  AC_MSG_CHECKING(for apxs in /usr/local/apache/sbin and /usr/sbin)
  AC_PATH_PROG(APXS, apxs, NO_APXS, [/usr/local/apache/sbin:/usr/sbin:$PATH])
  if test -x $APXS; then
    AC_MSG_RESULT([found $APXS. Use --with-apxs to specify another.])
  else
    AC_MSG_RESULT(no)
  fi
fi

# and finally
if test -z "$APXS"; then
  AC_MSG_ERROR([apxs was not found. use --with-apxs to specify it.])
fi

# Get some variables we need for Makefile.in
apache_inc=`$APXS -q INCLUDEDIR`
apache_conf=`$APXS -q SYSCONFDIR`
apache_prefix=`$APXS -q PREFIX`
apache_bin=`$APXS -q SBINDIR`
extra_cppflags="$extra_cppflags `$APXS -q EXTRA_CPPFLAGS`"

if ! test -f "$apache_inc/apr.h"; then
  if test -z "$apr_inc"; then
    AC_MSG_ERROR([apr.h is not in your Apache include dir as reported by apxs. Use --with-apr-config to have apr-config tell us where to find it.])
  fi
fi

AC_CHECKING(for NSPR)

# check for --with-nspr
AC_MSG_CHECKING(for --with-nspr)
AC_ARG_WITH(nspr, [  --with-nspr=PATH 	Netscape Portable Runtime (NSPR) directory],
[
  if test -e "$withval"/include/nspr.h -a -d "$withval"/lib
  then
    AC_MSG_RESULT([using $withval])
    NSPRDIR=$withval
    nspr_inc="-I$NSPRDIR/include"
    nspr_lib="-L$NSPRDIR/lib"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-nspr-inc
AC_MSG_CHECKING(for --with-nspr-inc)
AC_ARG_WITH(nspr-inc, [  --with-nspr-inc=PATH        Netscape Portable Runtime (NSPR) include file directory],
[
  if test -e "$withval"/nspr.h
  then
    AC_MSG_RESULT([using $withval])
    nspr_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-nspr-lib
AC_MSG_CHECKING(for --with-nspr-lib)
AC_ARG_WITH(nspr-lib, [  --with-nspr-lib=PATH        Netscape Portable Runtime (NSPR) library directory],
[
  if test -d "$withval"
  then
    AC_MSG_RESULT([using $withval])
    nspr_lib="-L$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# if NSPR is not found yet, try pkg-config

# last resort
if test -z "$nspr_inc" -o -z "$nspr_lib"; then
  AC_MSG_CHECKING(for nspr with pkg-config)
  AC_PATH_PROG(PKG_CONFIG, pkg-config)
  if test -n "$PKG_CONFIG"; then
    if $PKG_CONFIG --exists nspr; then
      nspr_inc=`$PKG_CONFIG --cflags-only-I nspr`
      nspr_lib=`$PKG_CONFIG --libs-only-L nspr`
    else
      AC_MSG_ERROR([NSPR not found, specify with --with-nspr.])
    fi
  fi
fi 

AC_CHECKING(for NSS)

# check for --with-nss
AC_MSG_CHECKING(for --with-nss)
AC_ARG_WITH(nss, [  --with-nss=PATH 	Network Security Services (NSS) directory],
[
  if test -e "$withval"/include/nss.h -a -d "$withval"/lib
  then
    AC_MSG_RESULT([using $withval])
    NSSDIR=$withval
    nss_inc="-I$NSSDIR/include"
    nss_lib="-L$NSSDIR/lib"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-nss-inc
AC_MSG_CHECKING(for --with-nss-inc)
AC_ARG_WITH(nss-inc, [  --with-nss-inc=PATH         Network Security Services (NSS) include directory],
[
  if test -e "$withval"/nss.h
  then
    AC_MSG_RESULT([using $withval])
    nss_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-nss-lib
AC_MSG_CHECKING(for --with-nss-lib)
AC_ARG_WITH(nss-lib, [  --with-nss-lib=PATH         Network Security Services (NSS) library directory],
[
  if test -d "$withval"
  then
    AC_MSG_RESULT([using $withval])
    nss_lib="-L$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# if NSS is not found yet, try pkg-config

# last resort
if test -z "$nss_inc" -o -z "$nss_lib"; then
  AC_MSG_CHECKING(for nss with pkg-config)
  AC_PATH_PROG(PKG_CONFIG, pkg-config)
  if test -n "$PKG_CONFIG"; then
    if $PKG_CONFIG --exists nss; then
      nss_inc=`$PKG_CONFIG --cflags-only-I nss`
      nss_lib=`$PKG_CONFIG --libs-only-L nss`
    else
      AC_MSG_ERROR([NSS not found, specify with --with-nss.])
    fi
  fi
fi

nspr_dir=`echo "$nspr_lib" | sed 's/\/lib[[/]]*$//' | sed 's/-L//'`
nss_dir=`echo "$nss_lib" | sed 's/\/lib[[/]]*$//' | sed 's/-L//'`

AX_CHECK_DEFINE(nss3/sslproto.h, TLS_RSA_WITH_AES_128_GCM_SHA256, gcm=$enableval, gcm=no)
if test "$gcm" = yes; then
   extra_cppflags="$extra_cppflags -DENABLE_GCM"
   echo "ENABLE_GCM=1" > test/variable.py
else
   echo "ENABLE_GCM=0" > test/variable.py
fi

AX_CHECK_DEFINE(nss3/sslproto.h, TLS_RSA_WITH_AES_256_GCM_SHA384, sha384=$enableval, sha384=no)
if test "$sha384" = yes; then
   extra_cppflags="$extra_cppflags -DENABLE_SHA384"
   echo "ENABLE_SHA384=1" >> test/variable.py
else
   echo "ENABLE_SHA384=0" >> test/variable.py
fi

AX_CHECK_DEFINE(nss3/sslproto.h, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, chacha20=yes, chacha20=no)
if test "$chacha20" = yes; then
   extra_cppflags="$extra_cppflags -DENABLE_CHACHA20"
   echo "ENABLE_CHACHA20=1" >> test/variable.py
else
   echo "ENABLE_CHACHA20=0" >> test/variable.py
fi

CPPFLAGS="$CPPFLAGS $nspr_inc"
AX_CHECK_DEFINE(nss3/ssl.h, SSL_ENABLE_SERVER_DHE, server_dhe=yes, server_dhe=no)
if test "$server_dhe" = yes; then
   extra_cppflags="$extra_cppflags -DENABLE_SERVER_DHE"
   echo "ENABLE_SERVER_DHE=1" >> test/variable.py
else
   echo "ENABLE_SERVER_DHE=0" >> test/variable.py
fi

# Substitute values
AC_SUBST(APXS)
AC_SUBST(apr_inc)
AC_SUBST(apache_inc)
AC_SUBST(apache_conf)
AC_SUBST(apache_prefix)
AC_SUBST(apache_bin)
AC_SUBST(nspr_inc)
AC_SUBST(nspr_lib)
AC_SUBST(nss_inc)
AC_SUBST(nss_lib)
AC_SUBST(nspr_dir)
AC_SUBST(nss_dir)
AC_SUBST(extra_cppflags)

# Write config.status and the Makefile
AC_OUTPUT(Makefile nss.conf gencert)

chmod +x gencert
