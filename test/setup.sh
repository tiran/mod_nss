#!/bin/sh
currentpath=`pwd`
server_uid=$USER
server_gid=$USER
server_port=8000
server_name=`hostname`

while [[ $# > 1 ]]
do
key="$1"

case $key in
    -s|--sni)
    SNI="$2"
        shift # past argument
    ;;
    *)
            # unknown option
    ;;
esac
shift # past argument or value
done

DBPREFIX=$1

test_root=$currentpath/work/httpd
test_root_esc=`echo ${test_root} | sed -e 's/\\//\\\\\\//g'`

if [ -e $test_root ]; then
    if [ $# -gt 0 -a "$1X" = "forceX" ]; then
        rm -rf work
    else
        echo "Test directory already exists"
        exit 1
    fi
fi

./createinstance.sh ${test_root}
cp printenv.pl ${test_root}/cgi-bin
chmod 755 ${test_root}/cgi-bin/printenv.pl

cp ../.libs/libmodnss.so ${test_root}/lib
cp ../nss_pcache ${test_root}/bin

echo "Generating a new certificate database..."
bash ../gencert ${DBPREFIX}${test_root}/alias $SNI > /dev/null 2>&1
echo internal:httptest > ${test_root}/conf/password.conf

# Export the CA cert
certutil -L -d ${DBPREFIX}${test_root}/alias -n cacert -a > ${test_root}/alias/ca.pem

# Export the client cert
cd ${test_root}
echo password > pw
echo httptest > dbpw
pk12util -o alpha.p12 -d ${DBPREFIX}${test_root}/alias -n alpha -w pw -k dbpw
openssl pkcs12  -in alpha.p12 -clcerts -nokeys -out alpha.crt -passin pass:`cat pw`
openssl pkcs12  -in alpha.p12 -nocerts -nodes -out alpha.key -passin pass:`cat pw`
pk12util -o beta.p12 -d ${DBPREFIX}${test_root}/alias -n beta -w pw -k dbpw
openssl pkcs12  -in beta.p12 -clcerts -nokeys -out beta.crt -passin pass:`cat pw`
openssl pkcs12  -in beta.p12 -nocerts -nodes -out beta.key -passin pass:`cat pw`
/bin/rm -f pw dbpw
cd -

if [ -f ${test_root}/sedfile ]
then
        rm ${test_root}/sedfile
fi

echo "s/::TEST_ROOT::/${test_root_esc}/g" >> ${test_root}/sedfile
echo "s/::SERVER_ROOT::/${test_root_esc}/g" >> ${test_root}/sedfile
echo "s/::SERVER_PORT::/${server_port}/g" >> ${test_root}/sedfile
echo "s/::SERVER_NAME::/${server_name}/g" >> ${test_root}/sedfile
echo "s/::SERVER_UID::/${server_uid}/g" >> ${test_root}/sedfile
echo "s/::SERVER_GID::/${server_gid}/g" >> ${test_root}/sedfile

cat httpd.conf.tmpl | sed  -f ${test_root}/sedfile > ${test_root}/conf/httpd.conf
