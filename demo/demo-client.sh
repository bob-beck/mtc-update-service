#!/bin/sh
# The demo TLS client: openssl s_client connecting on an interval with the
# update service's current output, one summary line per connection. Each
# run is a fresh s_client, since it reads its files once at startup.
#
# Usage: cd <demo dir> && sh /path/to/demo-client.sh [rp dir] [port] [interval seconds]
# OPENSSL is the install directory of an openssl built from the mtc-stack
# branch; unset, the demo layout's ../openssl-install is used. mtc (from
# cloudflare-mtc) is used to describe the certificate received.

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
RP=${1:-rp/32473.1078}
PORT=${2:-4433}
INTERVAL=${3:-10}
CA_ID=$(basename "$RP")
LAST=${TMPDIR:-/tmp}/demo-client-cert.$$.pem
trap 'rm -f "$LAST"' EXIT

while [ ! -f "$RP/subtrees.txt" ]; do
	echo "waiting for $RP/subtrees.txt"
	sleep 5
done

while :; do
	out=$("$OPENSSL/bin/openssl" s_client -connect "localhost:$PORT" -tls1_3 \
		-no-CAfile -no-CApath -no-CAstore \
		-mtc_cas "$RP/ca-cert.pem" \
		-mtc_cosigners "$RP/cosigners.pem" -mtc_cosigner_quorum 1 \
		-mtc_landmarks "$CA_ID:1:$RP/landmarks-1.txt" \
		-mtc_subtrees "$RP/subtrees.txt" \
		-showcerts </dev/null 2>&1) || true
	verify=$(printf '%s\n' "$out" | sed -n 's/.*Verify return code: //p' | tail -1)
	if [ -z "$verify" ]; then
		result="no handshake: $(printf '%s\n' "$out" | grep -v '^$' | tail -1)"
	else
		key=$(printf '%s\n' "$out" | sed -n 's/^ *a:PKEY: \([^;]*\);.*/\1/p' | head -1)
		printf '%s\n' "$out" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' |
			sed -n '1,/-----END CERTIFICATE-----/p' >"$LAST"
		cert=$(mtc inspect cert "$LAST" 2>/dev/null |
			awk '{gsub(/  +/, " ")} /^serial/ {s=$0} /^subtree/ {t=$0} /^signatures none/ {g="landmark-relative"} /^signature / {n++}
			     END {if (s == "") exit; if (g == "") g = n " signature(s)"; print s "; " t "; " g}')
		result="verify: $verify; ${cert:-no certificate}; key ${key:-unknown}"
	fi
	latest=$(head -1 "$RP/landmarks-1.txt" 2>/dev/null)
	vetted=$(grep -vc '^#' "$RP/subtrees.txt" 2>/dev/null || echo 0)
	echo "$(date +%H:%M:%S) client has landmarks up to $latest, $vetted vetted subtrees"
	echo "$(date +%H:%M:%S) $result"
	echo "$(date +%H:%M:%S) next connection in ${INTERVAL}s"
	sleep "$INTERVAL"
done
