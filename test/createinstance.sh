#!/bin/sh
#
# Make a temporary Apache instance for testing.

function create_content_dirs {
    local dir=$1

    mkdir $1

    # Create the content
    mkdir $dir/rc4_cipher
    mkdir $dir/openssl_rc4_cipher
    mkdir $dir/openssl_aes_cipher
    mkdir $dir/acl
    mkdir $dir/protocolssl2
    mkdir $dir/protocolssl3
    mkdir $dir/protocoltls1
    mkdir $dir/protocoltls11
    mkdir $dir/protocoltls12
    mkdir $dir/proxydata

    cat > $dir/index.html << EOF
    <html>
    Basic index page for $dir
    </html
EOF

    cp $dir/index.html $dir/acl/aclS01.html
    cp $dir/index.html $dir/acl/aclS02.html
    cp $dir/index.html $dir/acl/aclS03.html
    cp $dir/index.html $dir/secret-test.html
    cp $dir/index.html $dir/protocolssl2/index.html
    cp $dir/index.html $dir/protocolssl3/index.html
    cp $dir/index.html $dir/protocoltls1/index.html
    cp $dir/index.html $dir/protocoltls11/index.html
    cp $dir/index.html $dir/protocoltls12/index.html
    cp $dir/index.html $dir/proxydata/index.html
}

target=$1

echo "Creating instance in $target"
mkdir -p $target

# Make the default server root
cd $target
mkdir alias
mkdir bin
mkdir conf
mkdir conf.d
mkdir logs
mkdir run
mkdir cgi-bin
mkdir lib

touch conf.d/empty.conf

# Create the content directories
create_content_dirs content
count=1
while test $count -lt 26 ; do
    create_content_dirs "sni${count}"
    count=`expr $count + 1`
done

ln -s /etc/httpd/modules modules

dn="E=alpha@`hostname`,CN=Frank Alpha,UID=alpha,OU=People,O=example.com,C=US"
cat > conf/htpasswd << EOF
/${dn}:xxj31ZMTZzkVA
EOF

# Create start/stop scripts

cat << EOF >  start
#!/bin/sh
MALLOC_CHECK_=3
MALLOC_PERTURB=9
HTTPD=/usr/sbin/httpd
#valgrind --leak-check=full --log-file=valgrind.out --trace-children=yes --track-origins=yes\$HTTPD -X -k start -d . -f ./conf/httpd.conf
\$HTTPD -k start -d . -f ./conf/httpd.conf
EOF

cat << EOF > stop
#!/bin/sh
HTTPD=/usr/sbin/httpd
\$HTTPD -k stop -d . -f ./conf/httpd.conf
EOF

chmod 0755 start stop
