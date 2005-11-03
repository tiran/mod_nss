#!/bin/sh -xv

# This script provides an example of how to build the various flavors
# of the mod_nss rpm.  If you don't have a source tarball, you
# can create one from checking out the source tree (which you presumably
# have if you have checked out this script) and putting it in
# SOURCES/mod_nss-1.0.tar.gz.  The things you need to define below
# are:
# RPM_PLATFORM - one of RHEL3, RHEL4, FC3, FC4, etc. - should correspond
# to our internal build platform naming convention
# FLAVOR - use dbg for debug builds and opt for optimized builds
# NSPRDIR - directory holding NSPR include and lib directories
# NSSDIR - directory holding NSS include and lib directories

mkdirs() {
        for d in "$@" ; do
                if [ -d $d ]; then
                        mv $d $d.deleted
                        rm -rf $d.deleted &
                fi
                mkdir -p $d
        done
}

mkdirs SOURCES BUILD SRPMS RPMS
cd SOURCES
cvs -d $FEDCVSROOT co -d mod_nss-1.0 mod_nss
tar cf - mod_nss-1.0 | gzip > mod_nss-1.0.tar.gz
rm -rf mod_nss-1.0
cd ..

# define PLATFORM to be RHEL3, RHEL4, FC3, FC4, etc.
RPM_PLATFORM=RHEL4
# define FLAVOR to be dbg or opt for debug or optimized build
FLAVOR=dbg
# root dir for RPM built and temp files
ABS_TOPDIR=`pwd`
arch=`uname -i`
#mkdirs RPMS/$arch

# now define the locations of our components
NSPRDIR=/share/builds/components/nspr/v4.4.1/RHEL4_x86_gcc3_DBG.OBJ
NSSDIR=/share/builds/components/nss/NSS_3_9_3_RTM/RHEL4_x86_gcc3_DBG.OBJ

rpmbuild --define "_topdir $ABS_TOPDIR" --define "_sourcedir $ABS_TOPDIR/SOURCES" --define "_rpmdir $ABS_TOPDIR/RPMS" --define "_srcrpmdir $ABS_TOPDIR/SRPMS" --define "ARCH $arch" --define "flavor $FLAVOR" --define "platform $RPM_PLATFORM" --define "nsprincdir $NSPRDIR/include" --define "nsprlibdir $NSPRDIR/lib" --define "nssincdir $NSSDIR/include" --define "nsslibdir $NSSDIR/lib" --nodeps -ba mod_nss.spec
