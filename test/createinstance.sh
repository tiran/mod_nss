#!/bin/sh
#
# Make a temporary Apache instance for testing.

if [ " $#" -eq 0 ]; then
    echo "Usage: $0 /path/to/instance"
    exit 1
fi
target=$1

echo "Creating instance in $target"
mkdir -p $target

cd $target
mkdir alias
mkdir bin
mkdir conf
mkdir conf.d
mkdir logs
mkdir run
mkdir content
mkdir cgi-bin
mkdir lib

# Create the content
mkdir content/rc4_cipher
mkdir content/acl
mkdir content/protocolssl2
mkdir content/protocolssl3
mkdir content/protocoltls1
mkdir content/protocoltls11
mkdir content/protocoltls12

cat > content/index.html << EOF
<html>
Basic index page
</html
EOF
cp content/index.html content/acl/aclS01.html
cp content/index.html content/acl/aclS02.html
cp content/index.html content/acl/aclS03.html
cp content/index.html content/secret-test.html
cp content/index.html content/protocolssl2/index.html
cp content/index.html content/protocolssl3/index.html
cp content/index.html content/protocoltls1/index.html
cp content/index.html content/protocoltls11/index.html
cp content/index.html content/protocoltls12/index.html

ln -s /etc/httpd/modules modules

dn="E=alpha@`hostname`,CN=Frank Alpha,UID=alpha,OU=People,O=example.com,C=US"
cat > conf/htpasswd << EOF
/${dn}:xxj31ZMTZzkVA
EOF

# Create start/stop scripts

cat << EOF >  start
#!/bin/sh
HTTPD=/usr/sbin/httpd
\$HTTPD -k start -d . -f ./conf/httpd.conf
EOF

cat << EOF > stop
#!/bin/sh
HTTPD=/usr/sbin/httpd
\$HTTPD -k stop -d . -f ./conf/httpd.conf
EOF

chmod 0755 start stop
