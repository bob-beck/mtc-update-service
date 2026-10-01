#!/bin/sh
# The demo TLS server: openssl s_server serving one connection at a time
# from the subscriber's chain file, restarted after each so every
# connection sees the current certificates. s_server loads -tai_chains
# once at startup and never re-reads it.
#
# Usage: cd <demo dir> && sh /path/to/demo-server.sh [chain file] [port]
# OPENSSL is the install directory of an openssl built from the mtc-stack
# branch; unset, the demo layout's ../openssl-install is used.

set -eu

OPENSSL=${OPENSSL:-../openssl-install}
if [ ! -x "$OPENSSL/bin/openssl" ]; then
	echo "no openssl at $OPENSSL/bin/openssl; set OPENSSL to the install directory of an openssl built from the mtc-stack branch" >&2
	exit 1
fi
if ! "$OPENSSL/bin/openssl" s_client -help 2>&1 | grep -q -- -mtc_cas; then
	echo "$OPENSSL/bin/openssl has no Merkle Tree Certificate support; it must be built from the mtc-stack branch" >&2
	exit 1
fi
CHAINS=${1:-servers/www/chains.pem}
PORT=${2:-4433}

if [ ! -f fallback.pem ]; then
	"$OPENSSL/bin/openssl" req -x509 -newkey ed25519 -nodes -subj /CN=fallback -days 30 \
		-keyout fallback-key.pem -out fallback.pem 2>/dev/null
fi
while [ ! -f "$CHAINS" ]; do
	echo "waiting for $CHAINS"
	sleep 5
done

if nc -z localhost "$PORT" 2>/dev/null; then
	echo "something is already listening on port $PORT" >&2
	exit 1
fi

mkdir -p logs
n=0
while :; do
	certs=$(grep -c 'BEGIN CERTIFICATE PROPERTIES' "$CHAINS")
	echo "$(date +%H:%M:%S) listening on $PORT with $certs certificates from $CHAINS"
	if "$OPENSSL/bin/openssl" s_server -accept "$PORT" -tls1_3 -www -naccept 1 \
		-cert fallback.pem -key fallback-key.pem \
		-tai_chains "$CHAINS" </dev/null >>logs/server.log 2>&1; then
		n=$((n + 1))
		echo "$(date +%H:%M:%S) served connection $n; restarting with the current chain file"
	else
		echo "$(date +%H:%M:%S) s_server failed:" >&2
		grep ':error:' logs/server.log | tail -3 | sed 's/^/    /' >&2
		echo "    (full output in logs/server.log; retrying in 5s)" >&2
		sleep 5
	fi
	sleep 0.2
done
