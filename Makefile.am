## This is the shared library to be built
lib_LTLIBRARIES = libmodnss.la

bin_PROGRAMS = nss_pcache

nss_pcache_SOURCES = nss_pcache.c

man8_MANS =				\
	gencert.8			\
	nss_pcache.8			\
	$(NULL)

install-data-hook:
	@for i in $(man8_MANS) ; do gzip -f $(DESTDIR)$(man8dir)/$$i ; done

## Define the source file for the module
libmodnss_la_SOURCES = mod_nss.c nss_engine_config.c nss_engine_init.c nss_engine_io.c nss_engine_kernel.c nss_engine_log.c nss_engine_pphrase.c nss_engine_vars.c nss_expr.c nss_expr_eval.c nss_expr_parse.y nss_expr_scan.l nss_util.c nss_engine_rand.c
libmodnss_la_LDFLAGS = -module -avoid-version

## Set the includes and libraries needed
INCLUDES = -I@apache_inc@ @nspr_inc@ @nss_inc@ @apr_inc@
LIBS = @nspr_lib@ @nss_lib@ -lssl3 -lsmime3 -lnss3 -lplc4 -lplds4 -lnspr4
EXTRA_CPPFLAGS=@extra_cppflags@

install-libLTLIBRARIES: libmodnss.la
	@APXS@ -i -a -n nss libmodnss.la
	if [ -d @apache_conf@/../conf.d ]; then \
	    if [ ! -f @apache_conf@/../conf.d/nss.conf ]; then \
		$(INSTALL_DATA) nss.conf @apache_conf@/../conf.d/nss.conf; \
	    fi \
	else \
	    if [ ! -f @apache_conf@/nss.conf ]; then \
		$(INSTALL_DATA) nss.conf @apache_conf@/nss.conf; \
	    fi \
	fi
	if [ -d @apache_conf@/../conf.d ]; then \
	    if [ -f @apache_conf@/../conf.d/ssl.conf ]; then \
		mv @apache_conf@/../conf.d/ssl.conf @apache_conf@/../conf.d/ssl.conf.old; \
	    fi \
	else \
	    if [ -f @apache_conf@/ssl.conf ]; then \
		mv @apache_conf@/ssl.conf @apache_conf@/ssl.conf.old; \
	    fi \
	fi

install-binPROGRAMS: $(bin_PROGRAMS)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(apache_bin)
	@list='$(bin_PROGRAMS)'; for p in $$list; do \
	  if test -f $$p; then \
	    echo " $(LIBTOOL)  --mode=install $(INSTALL_PROGRAM) $$p $(apache_bin)/`echo $$p|sed 's/$(EXEEXT)$$//'|sed '$(transform)'|sed 's/$$/$(EXEEXT)/'`"; \
	    $(LIBTOOL)  --mode=install $(INSTALL_PROGRAM) $$p $(apache_bin)/`echo $$p|sed 's/$(EXEEXT)$$//'|sed '$(transform)'|sed 's/$$/$(EXEEXT)/'`; \
	  else :; fi; \
	done
	@echo ""
	@echo "**********************   NOTE   **************************"
	@echo "To create a certificate database with a self-signed"
	@echo "certificate, use the gencert program that comes with"
	@echo "mod_nss."
	@echo "**********************   NOTE   **************************"
	@echo ""

nss_expr_scan.c: nss_expr_scan.l nss_expr_parse.h
	$(LEX) -Pnss_expr_yy -s -B nss_expr_scan.l
	sed -e '/$$Header:/d' <lex.nss_expr_yy.c >nss_expr_scan.c && rm -f lex.nss_expr_yy.c

nss_expr_parse.c nss_expr_parse.h: nss_expr_parse.y
	$(YACC) -d nss_expr_parse.y
	sed -e 's;yy;nss_expr_yy;g' \
	    -e '/#if defined(c_plusplus) || defined(__cplusplus)/,/#endif/d' \
	    <y.tab.c >nss_expr_parse.c && rm -f y.tab.c
	sed -e 's;yy;nss_expr_yy;g' \
	    <y.tab.h >nss_expr_parse.h && rm -f y.tab.h

LTCOMPILE = $(LIBTOOL) --mode=compile $(CC) $(DEFS) \
	$(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) \
	$(AM_CFLAGS) $(CFLAGS) $(EXTRA_CPPFLAGS)

LINK = $(LIBTOOL) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) \
	$(AM_LDFLAGS) $(LDFLAGS) -o $@

MAINTAINERCLEANFILES =		\
	*~			\
	Makefile.in		\
	aclocal.m4		\
	config.guess		\
	config.sub		\
	configure		\
	depcomp			\
	install-sh		\
	ltmain.sh		\
	missing			\
	ylwrap

test:
	cd test;	\
	./setup.sh;	\
	nosetests -v;	\
	cd ..

.PHONY: all test clean
