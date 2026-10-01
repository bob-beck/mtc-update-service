#!/bin/sh
# Start the whole demo in one terminal: CA, mirror, subscriber and update
# service, logging to logs/. Interrupting it stops everything. Re-running reuses
# the CA and mirror already created in the current directory.
#
# Usage: cd <demo dir> && sh /path/to/run.sh
# Needs mtc, mtc-subscriber and mtc-update-service on PATH.

set -eu

CA_ID=32473.1078
MIRROR_ID=32473.1079
CA_PORT=8080
MIRROR_PORT=8081
# Everything is shortened so the whole lifecycle plays out in a minute:
# certificates live 1m, the CA runs issuance every second and mints a
# landmark every 5s, the server is reissued once per landmark, and the
# client's landmark files are refreshed every 45s, so the client lags the
# server by several landmarks and is served a landmark-relative
# certificate for one it knows.
LIFETIME=${LIFETIME:-1m}
ISSUE_EVERY=${ISSUE_EVERY:-1s}
LANDMARK_INTERVAL=${LANDMARK_INTERVAL:-5s}
REISSUE_INTERVAL=${REISSUE_INTERVAL:-5s}
UPDATE_INTERVAL=${UPDATE_INTERVAL:-45s}
# The server's key type: mldsa44 or p256.
KEY_TYPE=${KEY_TYPE:-mldsa44}

PIDS=""
cleanup() {
	for p in $PIDS; do kill "$p" 2>/dev/null; done
}
trap cleanup EXIT INT TERM

wait_port() {
	i=0
	while ! nc -z localhost "$1" 2>/dev/null; do
		i=$((i + 1))
		[ $i -gt 100 ] && { echo "nothing listening on port $1" >&2; exit 1; }
		sleep 0.1
	done
}

mkdir -p logs

if [ ! -d ca ]; then
	mtc ca -p ca new --log 1 --prefix-url http://localhost:$CA_PORT \
		--max-lifetime $LIFETIME --landmark-interval $LANDMARK_INTERVAL --iana-oids $CA_ID
fi
if [ ! -d mirror ]; then
	mtc mirror -p mirror new $MIRROR_ID
	mtc mirror -p mirror add-log --log 1 ca/ca-cert.pem
fi

mtc mirror -p mirror serve --listen localhost:$MIRROR_PORT >logs/mirror.log 2>&1 &
PIDS="$PIDS $!"
wait_port $MIRROR_PORT

if ! grep -q "$MIRROR_PORT" ca/config.json; then
	mtc ca -p ca add-mirror --required http://localhost:$MIRROR_PORT mirror/cosigner-cert.pem
fi
mtc ca -p ca serve --listen localhost:$CA_PORT --issue-every $ISSUE_EVERY >logs/ca.log 2>&1 &
PIDS="$PIDS $!"
wait_port $CA_PORT

mtc-subscriber -ca-url http://localhost:$CA_PORT -out servers -tick 1s \
	-server www:localhost:$KEY_TYPE:$REISSUE_INTERVAL >logs/subscriber.log 2>&1 &
PIDS="$PIDS $!"

mtc-update-service -ca-cert ca/ca-cert.pem \
	-cosigner-cert mirror/cosigner-cert.pem -mirror-url http://localhost:$MIRROR_PORT \
	-interval $UPDATE_INTERVAL -out rp >logs/update-service.log 2>&1 &
PIDS="$PIDS $!"

DEMO=$(cd "$(dirname "$0")" && pwd)
cat <<EOF
Running: mirror, CA, subscriber, update service. Logs are in logs/;
Interrupting this script stops them. In two other terminals, from $PWD:

  sh $DEMO/demo-server.sh
  sh $DEMO/demo-client.sh

EOF

tail -f logs/subscriber.log logs/update-service.log
