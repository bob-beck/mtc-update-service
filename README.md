Merkle Tree Certificates Update Service end-to-end demo
=========================================

This demo runs a sort of complete Merkle Tree Certificate (MTC)
ecosystem on one machine: a CA with its issuance log, an independent
cosigning mirror, a subscriber that keeps a TLS server supplied with
certificates, a relying party update service that vets the CA's
landmarks for TLS clients, and an OpenSSL `s_server` and `s_client`
that do the handshake. Every component talks to the others only over
HTTP on localhost, or through files dropped in a directory, so each
could equally run on its own host.

It follows draft-ietf-plants-merkle-tree-certs-06 (MTC) and
draft-ietf-tls-trust-anchor-ids-05 (TAI).

Pre warning of what this is NOT:
--------------------------------

- THIS IS NOT THE WAY TO WRITE A CA - please do not use this code, it's a hack
  job for a demo.. It is not written or reviewed with anything like
  being a secure production service in mind. Using this code as a
  basis for being a production service would be really foolish. Please
  get a written for production CA and acme server and mirror if you want
  to be a real CA or mirror. DO NOT USE THIS IT IS TERRIBLE!

  If you think the demo code is terrible and you want to make a good
  one, please just write a good one, if you do, tell me, I'll throw
  this away and use it. Once real stuff is available for CAs, Acme,
  and log mirroring, I will probably just use that. Sending PR's to
  "improve this for production use" is probably a bad idea, like
  picking tasty corn to eat out of moose poop - it is a far better
  idea to simply get some corn and skip the step of deriving it from
  the moose faeces entirely. Thank you.

The pieces
----------

| Component | Program | Repository | Role in the draft |
|---|---|---|---|
| CA | `mtc ca` | `cloudflare-mtc` | MTC Section 5: issuance log, CA cosigner, landmarks |
| Mirror | `mtc mirror` | `cloudflare-mtc` | MTC Section 5.3 cosigner, c2sp.org/tlog-mirror |
| Subscriber | `mtc-subscriber` | `cloudflare-mtc` | Stands in for the server's ACME client (MTC Section 9) |
| Update service | `mtc-update-service` | `mtc-update-service` | The relying party's update service (MTC Section 7.4) |
| Server | `openssl s_server` | `openssl`, branch `mtc-stack` | Authenticating party (TAI Section 5.3) |
| Client | `openssl s_client` | `openssl`, branch `mtc-stack` | Relying party (TAI Section 5.2, MTC Section 7) |

Two things that would exist in a real deployment are deliberately absent:

- ACME. The subscriber drives issuance through the CA's own HTTP
  interface and writes the certificates where the server reads them. It
  is a drop-in stand-in for the server-to-ACME, ACME-to-CA and
  ACME-to-server legs.
- Distribution. Both the subscriber and the update service write their
  output into local directories. Getting those directories to a server or
  a client host is left to rsync, an HTTPS fetcher, or whatever the
  operator likes. In this demo everything reads them in place.

How the pieces fit
------------------

                 POST /queue, GET /1/cert/...          chains.pem
    Subscriber  ------------------------------>  CA  - - - - - - - ->  s_server
                                                  |
                                     tlog-mirror  |  push: checkpoints,
                                                  v  entries, subtree cosigs
                                                Mirror
                                                  ^
             GET /1/landmarks, /1/checkpoint      |  GET <origin>/checkpoint,
             (CA)                                 |  <origin>/tile/... (mirror)
    Update service  ------------------------------+
         |
         |  landmarks-1.txt, subtrees.txt, ca-cert.pem, cosigners.pem
         v
    rp/32473.7/   - - - - - - - - - - - - - - - - - - - - - - - ->  s_client

Dashed arrows are "files in a directory"; solid arrows are HTTP.

The CA appends every certificate it issues to an append-only issuance
log, signs a checkpoint and two subtrees covering the new entries, and
pushes the log to the mirror, which checks it is append-only, stores a
copy and cosigns. A *standalone* certificate carries an inclusion proof
plus the CA's and the mirror's cosignatures (MTC Section 6.3). Every
minute the CA designates the current tree size a *landmark*; entries
below it get a *landmark-relative* certificate carrying only an inclusion
proof and no signatures at all (Section 6.4).

A client can accept a landmark-relative certificate only if it already
trusts the hash of the landmark subtree the proof leads to. That is what
the update service provides: it fetches the CA's landmark list, fetches
the mirror's cosigned checkpoint, proves each landmark subtree consistent
with that checkpoint (Section 7.4), and writes the vetted hashes out. The
client advertises which landmarks it trusts in the TLS `trust_anchors`
extension (MTC Section 8.2.1), the server picks a matching
landmark-relative certificate, and the handshake verifies with no
signature anywhere in the certificate.

Prerequisites
-------------

- Go 1.27 or later.
- OpenSSL built from the `mtc-stack` branch of `~/openssl`, installed in
  `~/ossl-master`. The commands below use `$OPENSSL` for its binary.
- `~/cloudflare-mtc` and this repository checked out.

    export OPENSSL=$HOME/ossl-master/bin/openssl
    (cd ~/cloudflare-mtc && go build -o ~/bin/ ./cmd/...)
    (cd ~/mtc-update-service && go build -o ~/bin/ ./cmd/...)
    mkdir -p ~/mtc-demo && cd ~/mtc-demo

All remaining commands run from `~/mtc-demo`. Each long-running component
gets its own terminal.

Ports used: CA 8080, mirror 8081, TLS server 4433.

Step 1: the CA
--------------

The CA is identified by a trust anchor ID, a relative OID under the IANA
private enterprise arc. The demo uses `32473.7` (32473 is the IANA example
PEN). Its first issuance log is log 1, so the log's ID is `32473.7.0.1`
and its landmarks have IDs `32473.7.1.1.<L>`.

The defaults are short so the whole lifecycle plays out in minutes: a
10 minute maximum certificate lifetime and a landmark every minute, which
caps the active landmarks at 11 (Section 6.4.2).

    mtc ca -p ca new --log 1 --prefix-url http://localhost:8080 32473.7

This writes `ca/ca-key.pem` (the CA cosigner's ML-DSA-44 key),
`ca/ca-cert.pem` (an RFC 9925 unsigned certificate carrying the CA ID,
the cosigner key, the critical MTC CA extension and the mtc-tlog prefix
URL) and `ca/www/`, the directory served at the prefix URL.

Do not start it yet; the mirror has to exist first.

Step 2: the mirror
------------------

The mirror is a second, independent cosigner. It has its own ID,
`32473.8`, and its own ML-DSA-44 key. It never issues anything: it follows
the CA's log, verifies every push is append-only, keeps a full copy, and
cosigns checkpoints and subtrees.

    mtc mirror -p mirror new 32473.8
    mtc mirror -p mirror add-log --log 1 ca/ca-cert.pem
    mtc mirror -p mirror serve --listen localhost:8081

`mirror/cosigner-cert.pem` is the mirror's cosigner certificate; relying
parties that require the mirror's cosignature are configured with it.

Back in the CA, register the mirror as a required cosigner, so that
issuance fails rather than produce certificates the mirror has not seen:

    mtc ca -p ca add-mirror --required http://localhost:8081 mirror/cosigner-cert.pem

Step 3: start the CA
--------------------

    mtc ca -p ca serve --listen localhost:8080 --issue-every 10s

The CA now serves its log at `http://localhost:8080/1/` (checkpoint,
tiles, landmarks) and runs an issuance job every 10 seconds: it appends
queued requests, signs a checkpoint and the covering subtrees, pushes to
the mirror and collects its cosignatures, writes certificates, and
allocates a landmark when a minute has passed since the last one.

Useful things to look at while it runs:

    curl -s http://localhost:8080/1/checkpoint
    curl -s http://localhost:8080/1/landmarks
    curl -s http://localhost:8081/$(printf 'oid/1.3.6.1.4.1.32473.7.0.1' | shasum -a 256 | cut -c1-64)/checkpoint

The CA's checkpoint carries one signature line (the CA cosigner); the
mirror's copy carries two.

Step 4: the subscriber
----------------------

An MTC server does not hold one certificate that it renews. It requests
a new one at a regular interval, much shorter than the lifetime, and
keeps serving *every* certificate it holds for as long as each is valid.
Each landmark-relative certificate is pinned to the landmark that first
covered its entry, so a server that has been reissued every minute holds
one for every active landmark. A client whose landmark state is a few
minutes stale can still be served a signatureless certificate for a
landmark it knows.

The subscriber does this on the server's behalf. For each configured
server it posts a request to the CA on its interval, polls for the
standalone certificate and then for the landmark-relative one (the CA
answers 202 with Retry-After until the next landmark mints, as the ACME
`acme-optional-alternate` relation would), and rewrites that server's
chain file with all of its unexpired certificates:

    mtc-subscriber --ca-url http://localhost:8080 --out servers \
        --server www:localhost:p256:1m

The server spec is `name:dnsnames:keytype:interval`. This generates
`servers/www/key.pem` once and keeps `servers/www/chains.pem` current. The
chain file is in the format `s_server -tai_chains` reads: for each
certificate, a `CERTIFICATE PROPERTIES` block (TAI Section 7.4, carrying
the trust anchor ID and the landmark group patterns of MTC Section
8.2.1), the certificate, and the private key; landmark-relative
certificates first, since Section 8.2 says to prefer them, standalone
certificates last as the fallback. Expired certificates drop out on the
next rewrite.

Step 5: the TLS server
----------------------

    $OPENSSL s_server -accept 4433 -tls1_3 -www \
        -cert fallback.pem -key fallback-key.pem \
        -tai_chains servers/www/chains.pem

`fallback.pem` is any ordinary certificate, for clients that do not send
`trust_anchors` at all:

    $OPENSSL req -x509 -newkey ed25519 -nodes -subj /CN=fallback -days 30 \
        -keyout fallback-key.pem -out fallback.pem

`s_server` reads the chain file once at startup. To pick up the certs the
subscriber has added since, restart it. (A production server reloads;
this is a demo limitation, not a protocol one.)

Step 6: the update service
--------------------------

This is the component a client vendor would run. It trusts exactly what
the vendor ships, the CA certificate, the cosigner certificate and a
policy, and talks only to public endpoints. It is a tlog client, not a
mirror: it signs nothing and keeps no copy of the log.

    mtc-update-service --ca-cert ca/ca-cert.pem \
        --cosigner-cert mirror/cosigner-cert.pem \
        --mirror-url http://localhost:8081 \
        --require-cosigner 32473.8 \
        --interval 30s --out rp

Each run, for CA `32473.7` log 1:

1. Fetches `/1/landmarks` from the CA, checks it is well formed (Section
   6.4.3). The file is an unsigned CA claim; the vetting is what follows.
2. Fetches the mirror's cosigned checkpoint and verifies both signature
   lines against the shipped certificates. If the mirror has not yet
   cosigned a tree at least as large as the latest landmark, the newest
   landmarks are not vetted this run.
3. For each active landmark, derives its two subtrees (Section 6.4.1),
   computes their hashes from tiles fetched from the mirror, and verifies
   a subtree consistency proof against the cosigned checkpoint (Section
   4.4.3).
4. Writes `rp/32473.7/`:
   - `ca-cert.pem` and `cosigners.pem`, copied from the configured trust;
   - `landmarks-1.txt`, the CA's landmarks file as fetched;
   - `subtrees.txt`, one line `<CA ID> <log> <start> <end> <hash>` per
     subtree whose proof verified. A subtree whose proof did not verify is
     simply absent; the client then falls back to cosignatures for it.

Run it with `--once` to do a single pass and exit.

Step 7: the TLS client
----------------------

    $OPENSSL s_client -connect localhost:4433 -tls1_3 \
        -no-CAfile -no-CApath -no-CAstore \
        -mtc_cas rp/32473.7/ca-cert.pem \
        -mtc_cosigners rp/32473.7/cosigners.pem -mtc_cosigner_quorum 1 \
        -mtc_landmarks 32473.7:1:rp/32473.7/landmarks-1.txt \
        -mtc_subtrees rp/32473.7/subtrees.txt \
        -showcerts -tlsextdebug </dev/null

Expect `Verify return code: 0 (ok)` and, in the `-tlsextdebug` output, the
client's `trust_anchors` extension carrying the landmark group
`32473.7.2.1.<L>` for the newest landmark it holds a hash for. The
certificate the server sent is landmark-relative; confirm it has no
signatures:

    $OPENSSL s_client -connect localhost:4433 -tls1_3 \
        -no-CAfile -no-CApath -no-CAstore \
        -mtc_cas rp/32473.7/ca-cert.pem \
        -mtc_landmarks 32473.7:1:rp/32473.7/landmarks-1.txt \
        -mtc_subtrees rp/32473.7/subtrees.txt </dev/null 2>/dev/null \
      | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
      | mtc inspect cert /dev/stdin

`mtc inspect` prints the MTCProof: the subtree bounds, the inclusion
proof hashes, and an empty signature list.

Things to try
-------------

- **Stale client.** Stop the update service, wait a few minutes, connect
  again. The client still advertises its last vetted landmark group, the
  server still holds a landmark-relative certificate for one of those
  landmarks, and the handshake stays signatureless. After ten minutes
  every landmark the client knows has expired and the client drops back
  to advertising the bare CA ID; the server answers with a standalone
  certificate and verification uses the cosignatures instead.
- **Client with no landmarks.** Leave out `-mtc_landmarks` and
  `-mtc_subtrees`. The client advertises `32473.7`, gets a standalone
  certificate, and verification requires the CA's cosignature plus the
  mirror's (`-mtc_cosigner_quorum 1`).
- **Mirror lags.** Stop the mirror. Issuance stops (the mirror is
  required), so no new landmarks appear either. Restart it and watch the
  CA catch it up; the update service picks up the newly covered landmarks
  on its next run.
- **Untrusted hash.** Edit one hash in `rp/32473.7/subtrees.txt` and
  connect. The client fails verification for that landmark's certificate
  and does not fall back: a hashed subtree that does not match is a hard
  failure (Section 7.2 step 11).
- **Client authentication.** The same machinery works for client
  certificates: add a `--server` spec with `--client` to the subscriber,
  hand the chain file to `s_client -tai_chains`, and give `s_server`
  `-Verify 1 -mtc_cas` and the same landmark files.

What this demo is not
---------------------

- NOT THE WAY TO WRITE A CA - please do not use this code, it's a hack
  job for a demo.. It is not written or reviewed with anything like
  being a secure production service in mind. Using this code as a
  basis for being a production service would be really foolish. Please
  get a written for production CA and acme server and mirror if you want
  to be a real CA or mirror. DO NOT USE THIS IT IS TERRIBLE!
- Not a CA you should trust: `POST /queue` is open to anyone who can
  reach it, the key is a file on disk, and there is no validation of
  anything in a request.
- Not ACME: the subscriber speaks the CA's own HTTP interface.
- Not an update channel: the update service writes files; moving them to
  clients is up to you.
- Not multi-log: the CA serves only its current log, so a log switch
  (Section 12.2.1) is not exercised.
