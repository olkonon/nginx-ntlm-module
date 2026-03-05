#!/bin/bash

DIR="$(pwd)"

echo "Nginx version $NGINX_VERSION"
echo "Directory: $DIR"

mkdir -p $DIR/buildnginx/modules/nginx-ntlm-module/
wget -q "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
tar -xzf nginx-${NGINX_VERSION}.tar.gz
mv nginx-${NGINX_VERSION}/* $DIR/buildnginx/
mv src  $DIR/buildnginx/modules/nginx-ntlm-module/
mv config  $DIR/buildnginx/modules/nginx-ntlm-module/
cd $DIR/buildnginx
./configure --with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security' --with-pcre --with-http_ssl_module --add-module=./modules/nginx-ntlm-module/
make -j12
