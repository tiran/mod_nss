# BEGIN COPYRIGHT BLOCK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (C) 2005 Red Hat, Inc.
# All rights reserved.
# END COPYRIGHT BLOCK
%define product fedora
%define flavor 
%define _build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.%{flavor}.rpm
Summary: mod_nss
Name: mod_nss
Version: 1.0
Release: 1.%{platform}
License: Apache 2.0
Group: System Environment/Daemons
URL: http://directory.fedora.redhat.com/
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildPreReq: httpd-devel,apr-devel
# Without Autoreq: 0, rpmbuild finds all sorts of crazy
# dependencies that we don't care about, and refuses to install
Autoreq: 0
# Don't automatically generate provides list
AutoProv: 0
# Without Requires: something, rpmbuild will abort!
Requires: httpd,apr
Provides: mod_nss
Prefix: /opt/%{product}-ds/bin/admin

%description
An Apache 2.0 module for implementing crypto using the Mozilla NSS crypto libraries.  This supports SSLv3/TLSv1 including support for client certificate authentication.  NSS provides web applications with a FIPS 140 certified crypto provider and support for a full range of PKCS11 devices.

%prep
%setup -q

%build
%ifarch x86_64 ppc64 ia64 s390x
mycflags=-m64
%endif

if [ %{flavor} = 'dbg' ]; then
    flag=-g
else
    flag=-O2
fi

# configure requires nspr, nss, ldapsdk, adminutil
# if can't find apxs, use --with-apxs=/path/to/apxs
./configure --with-apr-config --with-nspr-inc=%{nsprincdir} --with-nspr-lib=%{nsprlibdir} --with-nss-inc=%{nssincdir} --with-nss-lib=%{nsslibdir}
CFLAGS="$flag $mycflags" make

%install
# we don't really want to install this in the system Apache modules dir
%{__mkdir_p} $RPM_BUILD_ROOT/%{prefix}/lib
%{__mkdir_p} $RPM_BUILD_ROOT/%{prefix}/admin/bin
install -m 755 .libs/libmodnss.so $RPM_BUILD_ROOT%{prefix}/lib
install -m 755 nss_pcache $RPM_BUILD_ROOT%{prefix}/admin/bin

%clean
rm -rf $RPM_BUILD_ROOT/$RPM_INSTALL_PREFIX

%files
# rather than listing individual files, we just package (and own)
# the entire ldapserver directory - if we change this to put
# files in different places, we won't be able to do this anymore
%defattr(-,root,root,-)
%{prefix}/lib/libmodnss.so
%{prefix}/admin/bin/nss_pcache

%changelog
* Thu Nov  3 2005 Richard Megginson <rmeggins@redhat.com> - 1.0
- Initial version


