Merkle Tree Certificates Update Service end-to-end demo
=========================================

This demo runs a sort of complete Merkle Tree Certificate (MTC)
ecosystem on one machine: a CA with its issuance log, an 'independent' (lol)
cosigning mirror, a subscriber that keeps a TLS server supplied with
certificates which fakes out the role that would normally be done by ACME,
, a relying party update service that vets the CA's
landmarks for TLS clients, and an OpenSSL `s_server` and `s_client`
that do the handshake. Every component talks to the others only over
HTTP on localhost, or through files dropped in a directory

It currntly follows draft-ietf-plants-merkle-tree-certs-06 (MTC) and
draft-ietf-tls-trust-anchor-ids-05 (TAI), other than it is using the
IANA assigned oids by default.

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
  a client host would normally be done by something shipping an update
  over the network or whatever. In this demo everything reads them in place.
  If you want things running on other machines, rsync or http or whatever
  them onto there.

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
    rp/32473.1078/ - - - - - - - - - - - - - - - - - - - - - - ->  s_client

Dashed arrows are "files in a directory"; solid arrows are HTTP.

The CA appends every certificate it issues to an append-only issuance
log, signs a checkpoint and two subtrees covering the new entries, and
pushes the log to the mirror, which checks it is append-only, stores a
copy and cosigns. A *standalone* certificate carries an inclusion proof
plus the CA's and the mirror's cosignatures (MTC Section 6.3).
Periodically (every 5 seconds in the demo) the CA designates the current
tree size a *landmark*; entries below it get a *landmark-relative*
certificate carrying only an inclusion proof and no signatures at all
(Section 6.4).

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

- Go 1.27 or later, with the directory `go install` puts binaries in
  on your `PATH`.
- A C compiler, Perl and make, to build OpenSSL.

Make one directory to hold everything in the demo, and do everything
below from inside it. The three repositories are cloned into it, the
demo's OpenSSL is installed into it, and the demo runs in it; nothing is
written anywhere else.

    mkdir <somewhere> && cd <somewhere>
    git clone https://github.com/openssl/openssl.git
    git clone https://github.com/bob-beck/cloudflare-mtc.git
    git clone https://github.com/bob-beck/mtc-update-service.git

The Merkle Tree Certificate and trust anchor identifier support for
OpenSSL is pull request [#33014](https://github.com/openssl/openssl/pull/33014).
Fetch it into a branch, build it, and install it into `openssl-install`
under the top-level directory. The demo scripts take the install
directory from the `OPENSSL` environment variable if it is set, and
otherwise use this one, `../openssl-install` from the demo directory.

    (cd openssl && git fetch origin pull/33014/head:mtc-stack && git checkout mtc-stack)
    (cd openssl && ./Configure --prefix="$PWD/../openssl-install" --libdir=lib \
        "-Wl,-rpath,$PWD/../openssl-install/lib" && make -j8 && make install_sw)
    export OPENSSL="$PWD/openssl-install"

The rpath lets the installed `openssl`, and the web servers built against
it below, find this OpenSSL's shared libraries without any environment
variable.

Build and install the Go programs, `mtc`, `mtc-subscriber` and
`mtc-update-service`:

    (cd cloudflare-mtc && go install ./cmd/...)
    (cd mtc-update-service && go install ./cmd/...)

Check that everything is found:

    $OPENSSL/bin/openssl version
    which mtc mtc-subscriber mtc-update-service

Ports used: CA 8080, mirror 8081, TLS server 4433, all on localhost.

Running the demo
----------------

Three scripts in `mtc-update-service/demo/`, each in its own terminal,
all run from a `demo` subdirectory of the top-level directory. Everything
they create lives under it.

Terminal 1, the infrastructure. On first run this creates the CA
(`32473.1078`) and the mirror (`32473.1079`), then starts the mirror, the
CA, the subscriber and the update service, logging each to `logs/`, and
tails the two interesting logs. Interrupting it stops them all. Run again, it
reuses the CA and mirror already there.

    mkdir demo && cd demo
    sh ../mtc-update-service/demo/run.sh

Terminal 2, the server. `s_server` serves one connection, exits, and is
started again with the subscriber's current chain file.

    cd demo
    sh ../mtc-update-service/demo/demo-server.sh

Terminal 3, the client. One `s_client` connection every 10 seconds with
the update service's current files, summarised to a few lines.

    cd demo
    sh ../mtc-update-service/demo/demo-client.sh

The OpenSSL commands have to be restarted to see updated files; both
`s_server` and `s_client` read their files once at startup. That is why
the two scripts loop. A real server or client would reload.

What you will see
-----------------

The timings are shortened so a certificate's whole life passes in a
minute, and the two sides update at very different rates:

| | |
|---|---|
| Certificate lifetime | 1 minute |
| CA issuance run | every 1 second |
| Landmark allocated | every 5 seconds |
| Server gets a new certificate | every 5 seconds (one per landmark) |
| Client's landmark files refreshed | every 45 seconds |
| Client connects | every 10 seconds |
| Server key | ML-DSA-44 |

Everything in the handshake that can be post-quantum is: the server's
key, the CA cosigner and the mirror cosigner are all ML-DSA-44, and the
key exchange is X25519MLKEM768. A landmark-relative certificate carries
no signature at all, which is the size saving the design is for.

So the server is always current, holding about a dozen live
certificates, one per active landmark, while the client learns about
landmarks only once per certificate lifetime and is usually several
landmarks behind the server.

**Terminal 1** tails `logs/subscriber.log` and `logs/update-service.log`.

The subscriber logs each request and what came back for it:

    13:08:16 www: requested 01790881696605083000-e07eabf146af1119
    13:08:17 www: 01790881696605083000-e07eabf146af1119: standalone certificate 12, expires 2026-10-01T19:09:17Z
    13:08:21 www: 01790881696605083000-e07eabf146af1119: landmark-relative certificate 12

The number is the entry's index in the issuance log. The standalone
certificate appears within a second of the request (the CA's next
issuance run); the landmark-relative one appears when the next landmark
is allocated, up to 5 seconds later. Both go into `servers/www/chains.pem`
and stay there until they expire a minute later.

The update service logs one line per run:

    13:08:46 32473.1078 log 1: reference size 31; vetted 10:[16,24) 10:[24,30) 11:[30,31) ...; unvetted none

`reference size` is the tree size of the mirror's cosigned checkpoint
that everything was proved against. Each `L:[a,b)` is a landmark number
and one of its subtrees, now proved consistent with that checkpoint and
written to `rp/32473.1078/subtrees.txt`. `unvetted` lists active
landmarks that could not be proved this run, normally because they are
newer than what the mirror has cosigned yet; they get picked up next
run. Before the CA's first landmark exists the service logs an error
fetching the landmarks file; it clears on the next run.

**Terminal 2** prints two lines per connection:

    13:09:00 listening on 4433 with 23 certificates from servers/www/chains.pem
    13:09:04 served connection 7; restarting with the current chain file

The certificate count is what that `s_server` loaded: roughly two per
live entry (standalone plus landmark-relative), so about two dozen at
steady state. `s_server`'s own output is in `logs/server.log`.

**Terminal 3** prints three lines per connection:

    13:09:04 client has landmarks up to 23, 14 vetted subtrees
    13:09:04 verify: 0 (ok); serial 0x100000000001a (log 1, index 26); subtree [26, 27); landmark-relative
    13:09:04 next connection in 10s

The first line is the client's state from its last update: the newest
landmark number in its landmarks file and how many subtree hashes it
trusts. The second is the result: the verify return code, then a
description of the certificate the server chose, from `mtc inspect`:
its serial (log number and entry index), the subtree its inclusion proof
leads to, and either `landmark-relative` (no signatures at all) or the
number of cosignatures it carries; then the certificate's key type as
`s_client` reports it.

What to notice:

- `verify: 0 (ok)` with `landmark-relative` is the point of the
  exercise: a certificate with no signature anywhere, accepted because
  the client trusts the hash of subtree `[26, 27)` from its update.
- The index in the served certificate lags the server's newest. The
  client advertises the landmark group for the newest landmark *it*
  knows (TAI `trust_anchors`, MTC Section 8.2.1), and the server picks a
  landmark-relative certificate pinned to a landmark at or below that.
  The server has newer ones, but this client cannot verify them yet.
- Between refreshes of the client's files the client is served the same
  certificate every time. When the files are refreshed, the `landmarks
  up to` number increases and the client requests the newer certificate,
  which the server then continues to serve it until the client's files
  are refreshed with another new landmark.

Things to try
-------------

The infrastructure script takes its timings from the environment; the CA
ones (`LIFETIME`, `LANDMARK_INTERVAL`) are baked into the CA at creation,
so changing those needs a fresh directory. `KEY_TYPE=p256` gives the
server an EC key instead of ML-DSA-44; the subscriber keeps the key it
generated, so changing that needs `servers/` removed.

- **A client that falls back.** Refresh the client less often than a
  certificate lives:

      UPDATE_INTERVAL=2m sh ../mtc-update-service/demo/run.sh

  For the first minute after each update the client is served
  landmark-relative certificates as before. Then every landmark it knows
  has expired, its advertised group matches nothing the server holds,
  and terminal 3 shows `2 signature(s)`: the server fell back to a
  standalone certificate and the client verified the CA's and the
  mirror's cosignatures instead. Verification still says `0 (ok)`.
- **A client with no landmark state at all.** Point the client script at
  a directory containing only `ca-cert.pem` and `cosigners.pem`, or run
  `s_client` by hand without `-mtc_landmarks` and `-mtc_subtrees`. Every
  connection gets a standalone certificate with two signatures.
- **The mirror as the gate.** Kill the `mtc mirror` process. Issuance
  stops, because the mirror is a required cosigner. The update service
  keeps vetting against the last checkpoint the mirror did cosign.
- **A hash the vendor got wrong.** Edit one hash in
  `rp/32473.1078/subtrees.txt`. The next connection that lands on that
  landmark's certificate fails verification outright; a trusted subtree
  whose hash does not match is a hard failure, not a fallback (MTC
  Section 7.2 step 11). The update service overwrites the file on its
  next run.

Running the pieces by hand
--------------------------

`run.sh` is only these commands. They are what you would run on separate
machines, with the localhost URLs replaced.

Create the CA and mirror once. The CA issues with the IANA-assigned OIDs;
without `--iana-oids` it uses the draft's experimental ones, and OpenSSL
accepts either.

    mtc ca -p ca new --log 1 --prefix-url http://localhost:8080 \
        --max-lifetime 1m --landmark-interval 5s --iana-oids 32473.1078
    mtc mirror -p mirror new 32473.1079
    mtc mirror -p mirror add-log --log 1 ca/ca-cert.pem

Start the mirror, register it with the CA as a required cosigner, start
the CA:

    mtc mirror -p mirror serve --listen localhost:8081
    mtc ca -p ca add-mirror --required http://localhost:8081 mirror/cosigner-cert.pem
    mtc ca -p ca serve --listen localhost:8080 --issue-every 1s

The subscriber, for one server named `www` with DNS name `localhost`, an
ML-DSA-44 key, reissued every 5 seconds (`-server` repeats for more
servers; the key type can also be `p256`):

    mtc-subscriber -ca-url http://localhost:8080 -out servers -tick 1s \
        -server www:localhost:mldsa44:5s

It keeps `servers/www/chains.pem` in the form `s_server -tai_chains`
reads: for each certificate a `CERTIFICATE PROPERTIES` block (TAI Section
7.4), the certificate and the private key, landmark-relative certificates
first, standalone last as the fallback, expired ones dropped.

The update service, trusting the CA certificate and requiring the
mirror's cosignature (each `-cosigner-cert` pairs with the `-mirror-url`
in the same position):

    mtc-update-service -ca-cert ca/ca-cert.pem \
        -cosigner-cert mirror/cosigner-cert.pem -mirror-url http://localhost:8081 \
        -interval 45s -out rp

It writes `rp/32473.1078/`: `ca-cert.pem` and `cosigners.pem` as given,
`landmarks-1.txt` as fetched from the CA, and `subtrees.txt` with one
line per vetted subtree in the form `-mtc_subtrees` reads. `-once` does a
single pass; `-max-active` caps the landmarks accepted.

The server and client commands the two scripts loop over:

    $OPENSSL/bin/openssl s_server -accept 4433 -tls1_3 -www -naccept 1 \
        -cert fallback.pem -key fallback-key.pem \
        -tai_chains servers/www/chains.pem

    $OPENSSL/bin/openssl s_client -connect localhost:4433 -tls1_3 \
        -no-CAfile -no-CApath -no-CAstore \
        -mtc_cas rp/32473.1078/ca-cert.pem \
        -mtc_cosigners rp/32473.1078/cosigners.pem -mtc_cosigner_quorum 1 \
        -mtc_landmarks 32473.1078:1:rp/32473.1078/landmarks-1.txt \
        -mtc_subtrees rp/32473.1078/subtrees.txt \
        -showcerts </dev/null

`fallback.pem` is any ordinary certificate, for clients that send no
`trust_anchors` at all; the server script makes one.

Adding `-tlsextdebug` to the `s_client` command shows the TLS extensions
on the wire, including the `trust anchors` extension in which the server
lists every trust anchor ID it can serve.

Using a real web server
-----------------------

The server side of the demo can be a real web server in place of
`s_server`: nginx, Apache httpd or HAProxy, each from a fork with support
for serving certificate chains selected by trust anchor identifier, and
each serving two virtual hosts, `www` and `api`, from their own chain
files. The rest of the demo is unchanged; the subscriber already keeps
both `servers/www/chains.pem` and `servers/api/chains.pem` current, and
the client script takes the name of the virtual host to ask for.

Each server is built against the OpenSSL installed in `openssl-install`
and runs from a configuration written inside the demo directory. Make
sure you have whatever that server needs to build in the first place;
only the parts specific to this demo are given here.

The forks are cloned into the top-level directory next to the others.
httpd also needs the APR and APR-util source trees in its `srclib/`:

    git clone https://github.com/bob-beck/nginx.git
    git clone https://github.com/bob-beck/apache-httpd.git
    git clone -b 1.7.x https://github.com/apache/apr.git apache-httpd/srclib/apr
    git clone -b 1.7.x https://github.com/apache/apr-util.git apache-httpd/srclib/apr-util
    git clone https://github.com/bob-beck/haproxy.git

**nginx** (`ssl_tai_certificate`, `ssl_tai_certificate_key`,
`ssl_tai_certificate_preference`). Point `auto/configure` at the demo
OpenSSL; it reports `checking for OpenSSL trust anchor identifiers ...
found`. The binary is `nginx/objs/nginx`; nothing is installed.

    cd nginx
    ./auto/configure --with-http_ssl_module \
        --with-cc-opt="-I$PWD/../openssl-install/include" \
        --with-ld-opt="-L$PWD/../openssl-install/lib -Wl,-rpath,$PWD/../openssl-install/lib"
    make -j8
    cd ..

**Apache httpd** (`SSLTAICertificateFile`, `SSLTAICertificateKeyFile`,
`SSLTAICertificatePreference`). A fresh clone has no `configure`;
httpd's `buildconf` generates it. Then configure with `--with-ssl`
pointing at the demo OpenSSL and install into `httpd-install` under the
top-level directory; configure reports `checking for
SSL_CTX_add1_credential... yes`.

    cd apache-httpd
    ./buildconf
    ./configure --prefix="$PWD/../httpd-install" --with-included-apr --enable-ssl \
        --with-ssl="$PWD/../openssl-install" --enable-mods-shared=ssl \
        LDFLAGS="-Wl,-rpath,$PWD/../openssl-install/lib"
    make -j8
    make install
    cd ..

**HAProxy** (`tai-chains`, `tai-keys`, `tai-preference` on `bind` and in
crt-lists). Build with `USE_TAI=1` and the demo OpenSSL; `haproxy -vv`
then lists `+TAI` and `Built with SSL library version : OpenSSL
4.2.0-dev`. The binary is `haproxy/haproxy`; nothing is installed.

    cd haproxy
    make -j8 TARGET=generic USE_OPENSSL=1 USE_TAI=1 \
        SSL_INC="$PWD/../openssl-install/include" SSL_LIB="$PWD/../openssl-install/lib" \
        ADDLIB="-Wl,-rpath,$PWD/../openssl-install/lib"
    cd ..

Then, with `run.sh` running in terminal 1 as before, run the chosen
server in terminal 2 in place of `demo-server.sh`:

    cd demo
    sh ../mtc-update-service/demo/demo-webserver.sh nginx

or `httpd` or `haproxy`. The script writes the server's configuration
under `demo/nginx/`, `demo/httpd/` or `demo/haproxy/`, starts the server
on port 4433, and reloads it whenever either chain file changes,
printing a line each time. The server keeps running between
connections; this is a server that reloads its certificates, which is
what `s_server` could not do. The server binaries are found relative to
the demo directory as laid out above; `NGINX_BIN`, `HAPROXY_BIN` and
`HTTPD_DIR` (the httpd install directory) override that.

In terminal 3 start the client but give it an argument 'both', and it
will connect to both virtual hosts each round, `www` and then `api`:

    sh ../mtc-update-service/demo/demo-client.sh both

Each virtual host serves certificates from its own chain file and lists
only its own trust anchor IDs; a client that sends no trust anchors at
all is served the ordinary fallback certificate.

Only one server can hold port 4433 at a time; stop `demo-server.sh` or
one web server before starting another. If it doesn't die cleanly
because the shell code sucks for your machine or whatever, hunting
it down and killing manually is an exercise for the reader. 

REMINDER: What this demo is not
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
