dnl  Copyright 2000-2004 The Apache Software Foundation
dnl  Licensed under the Apache License, Version 2.0 (the "License");
dnl  you may not use this file except in compliance with the License.
dnl  You may obtain a copy of the License at
dnl 
dnl       http://www.apache.org/licenses/LICENSE-2.0
dnl 
dnl  Unless required by applicable law or agreed to in writing, software
dnl  distributed under the License is distributed on an "AS IS" BASIS,
dnl  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl  See the License for the specific language governing permissions and
dnl  limitations under the License.

dnl #  start of module specific part
APACHE_MODPATH_INIT(nss)

dnl #  list of module object files
nss_objs="dnl
mod_nss.lo dnl
nss_engine_config.lo dnl
nss_engine_dh.lo dnl
nss_engine_init.lo dnl
nss_engine_io.lo dnl
nss_engine_kernel.lo dnl
nss_engine_log.lo dnl
nss_engine_mutex.lo dnl
nss_engine_pphrase.lo dnl
nss_engine_rand.lo dnl
nss_engine_vars.lo dnl
nss_expr.lo dnl
nss_expr_eval.lo dnl
nss_expr_parse.lo dnl
nss_expr_scan.lo dnl
nss_scache.lo dnl
nss_scache_dbm.lo dnl
nss_scache_shmcb.lo dnl
nss_scache_shmht.lo dnl
nss_util.lo dnl
nss_util_ssl.lo dnl
nss_util_table.lo dnl
"
dnl #  hook module into the Autoconf mechanism (--enable-nss option)
APACHE_MODULE(ssl, [SSL/TLS support (mod_nss)], $nss_objs, , no, [
#    APACHE_CHECK_SSL_TOOLKIT
    AC_CHECK_FUNCS(PR_Init)
    AC_CHECK_FUNCS(NSS_Initialize)
])

dnl #  end of module specific part
APACHE_MODPATH_FINISH

