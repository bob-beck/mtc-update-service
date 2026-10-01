/*
 * Copyright (c) 2026 Bob Beck <beck@obtuse.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// Command mtc-update-service is a relying party's update service for Merkle
// Tree Certificates (draft-ietf-plants-merkle-tree-certs-06, Section 7.4).
// It fetches a CA's landmark list and a checkpoint cosigned by the required
// cosigners, proves each active landmark subtree consistent with that
// checkpoint, and writes the result as the files OpenSSL's s_client loads
// with -mtc_landmarks and -mtc_subtrees.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	mtcupdate "github.com/bob-beck/mtc-update-service"
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	var cosignerCerts, mirrorURLs stringList
	caCert := flag.String("ca-cert", "", "CA certificate PEM (required)")
	caURL := flag.String("ca-url", "", "CA prefix URL; default is the one in the CA certificate")
	logNumber := flag.Uint("log", 1, "issuance log number")
	out := flag.String("out", "rp", "output directory")
	interval := flag.Duration("interval", time.Minute, "time between runs")
	maxActive := flag.Int("max-active", 0, "cap on active landmarks accepted, 0 for none")
	once := flag.Bool("once", false, "run once and exit")
	flag.Var(&cosignerCerts, "cosigner-cert", "required cosigner's certificate PEM (repeatable, paired with -mirror-url in order)")
	flag.Var(&mirrorURLs, "mirror-url", "the cosigner's tlog-mirror monitoring prefix URL (repeatable)")
	flag.Parse()
	if *caCert == "" {
		log.Fatal("-ca-cert is required")
	}
	if len(cosignerCerts) != len(mirrorURLs) {
		log.Fatal("-cosigner-cert and -mirror-url must be given the same number of times")
	}
	if *logNumber == 0 || *logNumber > 0xffff {
		log.Fatal("-log must be between 1 and 65535")
	}

	caPEM, err := os.ReadFile(*caCert)
	if err != nil {
		log.Fatal(err)
	}
	ca, err := mtcupdate.ParseCACertificatePEM(caPEM)
	if err != nil {
		log.Fatalf("%s: %v", *caCert, err)
	}
	p := &mtcupdate.Policy{CA: ca, LogNumber: uint16(*logNumber), CAURL: *caURL, MaxActive: *maxActive}
	var cosignersPEM []byte
	for i, path := range cosignerCerts {
		pemData, err := os.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		cs, err := mtcupdate.ParseCosignerCertificatesPEM(pemData)
		if err != nil {
			log.Fatalf("%s: %v", path, err)
		}
		if len(cs) != 1 {
			log.Fatalf("%s: want exactly one cosigner certificate, got %d", path, len(cs))
		}
		p.Mirrors = append(p.Mirrors, mtcupdate.Mirror{Cosigner: cs[0], URL: mirrorURLs[i]})
		cosignersPEM = append(cosignersPEM, pemData...)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		run(ctx, p, *out, caPEM, cosignersPEM)
		if *once {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(*interval):
		}
	}
}

func run(ctx context.Context, p *mtcupdate.Policy, out string, caPEM, cosignersPEM []byte) {
	now := time.Now()
	res, err := mtcupdate.Vet(ctx, p, now)
	if err != nil {
		log.Printf("%s log %d: %v", p.CA.ID, p.LogNumber, err)
		return
	}
	var vetted []string
	for _, v := range res.Vetted {
		vetted = append(vetted, fmt.Sprintf("%d:[%d,%d)", v.Landmark, v.Start, v.End))
	}
	var unvetted []string
	for _, l := range res.Unvetted {
		unvetted = append(unvetted, fmt.Sprintf("%d(size %d)", l.Number, l.TreeSize))
	}
	log.Printf("%s log %d: reference size %d; vetted %s; unvetted %s", p.CA.ID, p.LogNumber, res.ReferenceSize,
		orNone(vetted), orNone(unvetted))
	if err := mtcupdate.WriteOutput(out, p, caPEM, cosignersPEM, res, now); err != nil {
		log.Printf("%s log %d: writing output: %v", p.CA.ID, p.LogNumber, err)
	}
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, " ")
}
