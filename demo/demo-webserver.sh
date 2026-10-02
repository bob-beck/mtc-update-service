#!/bin/sh
# The demo TLS server as a real web server: nginx, Apache httpd or HAProxy,
# built against the demo's OpenSSL, serving two virtual hosts, www and api,
# each from its own subscriber chain file. The server is reloaded whenever
# a chain file changes. Everything it writes is under <demo dir>/<server>/.
#
# Usage: cd <demo dir> && sh /path/to/demo-webserver.sh nginx|httpd|haproxy [port]
#
# fallback.pem, the certificate for clients that send no trust anchors, is
# made here if demo-server.sh has not already made it, with the OpenSSL in
# OPENSSL or ../openssl-install. The server is found relative to the demo
# directory, as the README's layout has it, or through an environment
# variable:
#   NGINX_BIN   the nginx binary        (default ../nginx/objs/nginx)
#   HAPROXY_BIN the haproxy binary      (default ../haproxy/haproxy)
#   HTTPD_DIR   the httpd install directory (default ../httpd-install)
# nginx reads a variable named NGINX itself, so that name is not used.

set -eu

if [ $# -lt 1 ]; then
	echo "usage: $0 nginx|httpd|haproxy [port]" >&2
	exit 1
fi
KIND=$1
PORT=${2:-4433}
D=$PWD

for s in www api; do
	while [ ! -f servers/$s/chains.pem ]; do
		echo "waiting for servers/$s/chains.pem"
		sleep 5
	done
done
if [ ! -f fallback.pem ]; then
	OPENSSL=${OPENSSL:-../openssl-install}
	if [ ! -x "$OPENSSL/bin/openssl" ]; then
		echo "no openssl at $OPENSSL/bin/openssl to make fallback.pem with; set OPENSSL to the install directory" >&2
		exit 1
	fi
	if ! "$OPENSSL/bin/openssl" req -x509 -newkey ed25519 -nodes -subj /CN=fallback -days 30 -config /dev/null \
		-keyout fallback-key.pem -out fallback.pem; then
		echo "making fallback.pem with $OPENSSL/bin/openssl failed" >&2
		exit 1
	fi
fi

mkdir -p "$KIND"

case $KIND in
nginx)
	NGINX=${NGINX_BIN:-../nginx/objs/nginx}
	[ -x "$NGINX" ] || { echo "no nginx at $NGINX; set NGINX_BIN" >&2; exit 1; }
	mkdir -p nginx/logs nginx/temp
	cat > nginx/nginx.conf <<EOF
pid        nginx.pid;
error_log  logs/error.log;
events { }
http {
    access_log            logs/access.log;
    client_body_temp_path temp;
    proxy_temp_path       temp;
    fastcgi_temp_path     temp;
    uwsgi_temp_path       temp;
    scgi_temp_path        temp;

    ssl_certificate      $D/fallback.pem;
    ssl_certificate_key  $D/fallback-key.pem;
    ssl_tai_certificate_preference config;

    server {
        listen 127.0.0.1:$PORT ssl default_server;
        server_name www localhost;
        ssl_tai_certificate $D/servers/www/chains.pem;
        return 200 "www\n";
    }
    server {
        listen 127.0.0.1:$PORT ssl;
        server_name api;
        ssl_tai_certificate $D/servers/api/chains.pem;
        return 200 "api\n";
    }
}
EOF
	start() { "$NGINX" -p "$D/nginx" -c nginx.conf; }
	reload() { "$NGINX" -p "$D/nginx" -c nginx.conf -s reload; }
	stop() { "$NGINX" -p "$D/nginx" -c nginx.conf -s stop 2>/dev/null; }
	;;
haproxy)
	HAPROXY=${HAPROXY_BIN:-../haproxy/haproxy}
	[ -x "$HAPROXY" ] || { echo "no haproxy at $HAPROXY; set HAPROXY_BIN" >&2; exit 1; }
	cat fallback.pem fallback-key.pem > haproxy/fallback.pem
	cat > haproxy/crt-list.txt <<EOF
$D/haproxy/fallback.pem [tai-chains $D/servers/www/chains.pem tai-preference config] www localhost
$D/haproxy/fallback.pem [tai-chains $D/servers/api/chains.pem tai-preference config] api
EOF
	cat > haproxy/haproxy.cfg <<EOF
global
    pidfile $D/haproxy/haproxy.pid

defaults
    mode http
    timeout connect 2s
    timeout client 5s
    timeout server 5s

frontend demo
    bind 127.0.0.1:$PORT ssl crt-list $D/haproxy/crt-list.txt
    http-request return status 200 content-type text/plain lf-string "%[ssl_fc_sni]\n"
EOF
	start() { "$HAPROXY" -D -f haproxy/haproxy.cfg; }
	reload() { "$HAPROXY" -D -f haproxy/haproxy.cfg -sf "$(cat haproxy/haproxy.pid)"; }
	stop() { kill "$(cat haproxy/haproxy.pid)" 2>/dev/null; }
	;;
httpd)
	HTTPD=${HTTPD_DIR:-../httpd-install}
	[ -x "$HTTPD/bin/httpd" ] || { echo "no httpd at $HTTPD/bin/httpd; set HTTPD_DIR to the install directory" >&2; exit 1; }
	HTTPD=$(cd "$HTTPD" && pwd)
	mkdir -p httpd/logs httpd/www httpd/api
	echo www > httpd/www/index.html
	echo api > httpd/api/index.html
	cat > httpd/httpd.conf <<EOF
ServerRoot "$HTTPD"
PidFile "$D/httpd/httpd.pid"
ErrorLog "$D/httpd/logs/error.log"
LogLevel warn
Listen 127.0.0.1:$PORT
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule unixd_module modules/mod_unixd.so
SSLSessionCache none
ServerName www
<Directory "$D/httpd">
    Require all granted
</Directory>
<VirtualHost 127.0.0.1:$PORT>
    ServerName www
    ServerAlias localhost
    DocumentRoot "$D/httpd/www"
    SSLEngine on
    SSLCertificateFile "$D/fallback.pem"
    SSLCertificateKeyFile "$D/fallback-key.pem"
    SSLTAICertificateFile "$D/servers/www/chains.pem"
    SSLTAICertificatePreference config
</VirtualHost>
<VirtualHost 127.0.0.1:$PORT>
    ServerName api
    DocumentRoot "$D/httpd/api"
    SSLEngine on
    SSLCertificateFile "$D/fallback.pem"
    SSLCertificateKeyFile "$D/fallback-key.pem"
    SSLTAICertificateFile "$D/servers/api/chains.pem"
    SSLTAICertificatePreference config
</VirtualHost>
EOF
	start() { "$HTTPD/bin/httpd" -f "$D/httpd/httpd.conf" -k start; }
	reload() { "$HTTPD/bin/httpd" -f "$D/httpd/httpd.conf" -k graceful; }
	stop() { "$HTTPD/bin/httpd" -f "$D/httpd/httpd.conf" -k stop 2>/dev/null; }
	;;
*)
	echo "unknown server $KIND; want nginx, httpd or haproxy" >&2
	exit 1
	;;
esac

trap 'stop; exit' INT TERM EXIT

chains_state() { cat servers/www/chains.pem servers/api/chains.pem | cksum; }

start
echo "$(date +%H:%M:%S) $KIND listening on $PORT; virtual hosts www and api; configuration in $KIND/"
state=$(chains_state)
while :; do
	sleep 2
	new=$(chains_state)
	if [ "$new" != "$state" ]; then
		state=$new
		reload
		echo "$(date +%H:%M:%S) chain files changed; $KIND reloaded with $(grep -c 'BEGIN CERTIFICATE PROPERTIES' servers/www/chains.pem) certificates for www, $(grep -c 'BEGIN CERTIFICATE PROPERTIES' servers/api/chains.pem) for api"
	fi
done
