## This is the shared library to be built
lib_LTLIBRARIES = libmodnss.la

bin_PROGRAMS = nss_pcache

nss_pcache_SOURCES = nss_pcache.c

## Define the source file for the module
libmodnss_la_SOURCES = mod_nss.c nss_engine_config.c nss_engine_init.c nss_engine_io.c nss_engine_kernel.c nss_engine_log.c nss_engine_pphrase.c nss_engine_vars.c nss_expr.c nss_expr_eval.c ssl_expr_parse.y ssl_expr_scan.l nss_util.c

## Set the includes and libraries needed
INCLUDES = -I@apache_inc@ @nspr_inc@ @nss_inc@
LIBS = @nspr_lib@ @nss_lib@ -lnspr4 -lplc4 -lplds4 -lssl3 -lsmime3 -lnss3

install-libLTLIBRARIES: libmodnss.la
	@APXS@ -i -a -n nss libmodnss.la
	if [ ! -f @apache_conf@/nss.conf ]; then \
		$(INSTALL_DATA) nss.conf @apache_conf@/nss.conf; \
	fi

ssl_expr_scan.c: ssl_expr_scan.l ssl_expr_parse.h
	$(LEX) -Pssl_expr_yy -s -B ssl_expr_scan.l
	sed -e '/$$Header:/d' <lex.ssl_expr_yy.c >ssl_expr_scan.c && rm -f lex.ssl_expr_yy.c

ssl_expr_parse.c ssl_expr_parse.h: ssl_expr_parse.y
	$(YACC) -d ssl_expr_parse.y
	sed -e 's;yy;ssl_expr_yy;g' \
	    -e '/#if defined(c_plusplus) || defined(__cplusplus)/,/#endif/d' \
	    <y.tab.c >ssl_expr_parse.c && rm -f y.tab.c
	sed -e 's;yy;ssl_expr_yy;g' \
	    <y.tab.h >ssl_expr_parse.h && rm -f y.tab.h
