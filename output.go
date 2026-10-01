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

package mtcupdate

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// WriteOutput writes dir/<CA ID>/ for the relying party:
//
//	ca-cert.pem        the CA certificate, as configured
//	cosigners.pem      the cosigner certificates, as configured
//	landmarks-<N>.txt  the CA's landmark list, as fetched
//	subtrees.txt       the vetted subtree hashes, in the form OpenSSL's
//	                   -mtc_subtrees reads: <CA ID> <log> <start> <end> <hash>
//
// A subtree vetted on an earlier run keeps its line while its landmark is
// still active, even if this run could not vet it.
func WriteOutput(dir string, p *Policy, caCertPEM, cosignerCertsPEM []byte, res *Result, now time.Time) error {
	out := filepath.Join(dir, p.CA.ID.String())
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(out, "ca-cert.pem"), caCertPEM); err != nil {
		return err
	}
	if len(cosignerCertsPEM) > 0 {
		if err := writeFile(filepath.Join(out, "cosigners.pem"), cosignerCertsPEM); err != nil {
			return err
		}
	}
	if err := writeFile(filepath.Join(out, fmt.Sprintf("landmarks-%d.txt", p.LogNumber)), res.LandmarksFile); err != nil {
		return err
	}
	return writeFile(filepath.Join(out, "subtrees.txt"), subtreesFile(p, res, now, filepath.Join(out, "subtrees.txt")))
}

func subtreesFile(p *Policy, res *Result, now time.Time, prev string) []byte {
	id := p.CA.ID.String()
	log := strconv.Itoa(int(p.LogNumber))
	// Subtrees of the active landmarks, vetted or not.
	active := map[Subtree]bool{}
	for i := 0; i+1 < len(res.Landmarks); i++ {
		if sts, err := LandmarkSubtrees(res.Landmarks[i+1].TreeSize, res.Landmarks[i].TreeSize); err == nil {
			for _, s := range sts {
				active[s] = true
			}
		}
	}
	lines := map[Subtree]string{}
	if f, err := os.Open(prev); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) != 5 || fields[0] != id || fields[1] != log {
				continue
			}
			start, err1 := strconv.ParseUint(fields[2], 10, 64)
			end, err2 := strconv.ParseUint(fields[3], 10, 64)
			if err1 == nil && err2 == nil && active[Subtree{start, end}] {
				lines[Subtree{start, end}] = sc.Text()
			}
		}
		f.Close()
	}
	for _, v := range res.Vetted {
		lines[v.Subtree] = fmt.Sprintf("%s %s %d %d %s", id, log, v.Start, v.End, base64.StdEncoding.EncodeToString(v.Hash[:]))
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# vetted %s against a checkpoint of size %d\n", now.UTC().Format(time.RFC3339), res.ReferenceSize)
	// Oldest landmark first, as the landmark list runs newest first.
	for i := len(res.Landmarks) - 2; i >= 0; i-- {
		sts, err := LandmarkSubtrees(res.Landmarks[i+1].TreeSize, res.Landmarks[i].TreeSize)
		if err != nil {
			continue
		}
		for _, s := range sts {
			if line, ok := lines[s]; ok {
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
	}
	return b.Bytes()
}

func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
