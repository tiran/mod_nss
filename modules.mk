mod_nss.la: mod_nss.lo nss_engine_config.lo nss_engine_init.lo nss_engine_io.lo nss_engine_kernel.lo nss_engine_log.lo nss_engine_pphrase.lo nss_engine_vars.lo nss_expr.lo nss_expr_eval.lo nss_expr_parse.lo nss_expr_scan.lo nss_util.lo
	$(MOD_LINK) mod_nss.lo nss_engine_config.lo nss_engine_init.lo nss_engine_io.lo nss_engine_kernel.lo nss_engine_log.lo nss_engine_pphrase.lo nss_engine_vars.lo nss_expr.lo nss_expr_eval.lo nss_expr_parse.lo nss_expr_scan.lo nss_util.lo
DISTCLEAN_TARGETS = modules.mk
static =  mod_nss.la
shared = 
