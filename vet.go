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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

// A Mirror is a required cosigner together with the c2sp.org/tlog-mirror
// monitoring prefix URL its cosigned checkpoint and tiles are read from.
type Mirror struct {
	Cosigner *Cosigner
	URL      string
}

// A Policy is the relying party's configuration for one issuance log
// (draft-ietf-plants-merkle-tree-certs-06, Section 7.1).
type Policy struct {
	CA        *CA
	LogNumber uint16

	// CAURL overrides the prefix URL in the CA certificate.
	CAURL string

	// Mirrors are the cosigners whose checkpoints a subtree must be
	// consistent with (Section 7.4). All are required. With none, only the
	// CA cosigner's checkpoint is used.
	Mirrors []Mirror

	// MaxActive caps the active landmarks accepted; zero is no cap. The
	// newest beyond it are left unvetted (Section 7.4).
	MaxActive int
}

// A VettedSubtree is a landmark subtree whose hash has been proved
// consistent with the reference checkpoint.
type VettedSubtree struct {
	Landmark uint64
	Subtree
	Hash tlog.Hash
}

// A Result is one vetting run.
type Result struct {
	// LandmarksFile is the CA's landmark list as fetched.
	LandmarksFile []byte
	// Landmarks is LandmarksFile parsed, newest first, ending with the
	// first expired landmark.
	Landmarks []Landmark
	// ReferenceSize is the tree size everything was proved against.
	ReferenceSize int64
	Vetted        []VettedSubtree
	// Unvetted are the active landmarks that were not vetted this run.
	Unvetted []Landmark
}

type checkpoint struct {
	torchwood.Checkpoint
	fetcher *torchwood.TileFetcher
	source  string
}

// Vet runs Section 7.4 for p at time now: fetch the landmark list, fetch a
// checkpoint cosigned by every required cosigner, and prove each active
// landmark subtree consistent with it.
func Vet(ctx context.Context, p *Policy, now time.Time) (*Result, error) {
	caURL := p.CAURL
	if caURL == "" {
		caURL = p.CA.PrefixURL
	}
	if caURL == "" {
		return nil, errors.New("no CA URL configured and none in the CA certificate")
	}
	logURL := strings.TrimSuffix(caURL, "/") + "/" + strconv.Itoa(int(p.LogNumber))
	caFetcher, err := torchwood.NewTileFetcher(logURL)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	res.LandmarksFile, err = caFetcher.ReadEndpoint(ctx, "landmarks")
	if err != nil {
		return nil, fmt.Errorf("fetching landmarks: %w", err)
	}
	res.Landmarks, err = ParseLandmarks(res.LandmarksFile, now)
	if err != nil {
		return nil, err
	}

	origin := LogID(p.CA.ID, p.LogNumber).OriginString()
	caVerifier, err := (&Cosigner{ID: p.CA.ID, Key: p.CA.Key}).Verifier()
	if err != nil {
		return nil, err
	}
	ref, err := referenceCheckpoint(ctx, p, origin, caVerifier, caFetcher)
	if err != nil {
		return nil, err
	}
	res.ReferenceSize = ref.N
	hr := torchwood.TileHashReaderWithContext(ctx, ref.Tree, ref.fetcher)

	// Oldest active first, so a failure leaves it and everything newer
	// unvetted (Section 7.4).
	ls := res.Landmarks
	active := len(ls) - 1
	limit := active
	if p.MaxActive > 0 && limit > p.MaxActive {
		limit = p.MaxActive
	}
	failed := false
	for i := active - 1; i >= 0; i-- {
		l := ls[i]
		if failed || active-i > limit || l.TreeSize > uint64(ref.N) {
			res.Unvetted = append(res.Unvetted, l)
			continue
		}
		subtrees, err := LandmarkSubtrees(ls[i+1].TreeSize, l.TreeSize)
		if err != nil {
			return nil, fmt.Errorf("landmark %d: %w", l.Number, err)
		}
		for _, s := range subtrees {
			h, err := vetSubtree(ref, s, hr)
			if err != nil {
				failed = true
				res.Unvetted = append(res.Unvetted, l)
				break
			}
			res.Vetted = append(res.Vetted, VettedSubtree{Landmark: l.Number, Subtree: s, Hash: h})
		}
	}
	return res, nil
}

// vetSubtree computes the subtree hash from tiles authenticated against the
// reference checkpoint and verifies a subtree consistency proof (Section
// 4.4.3) between the two.
func vetSubtree(ref *checkpoint, s Subtree, hr tlog.HashReader) (tlog.Hash, error) {
	start, end := int64(s.Start), int64(s.End)
	h, err := torchwood.SubtreeHash(start, end, hr)
	if err != nil {
		return tlog.Hash{}, err
	}
	proof, err := torchwood.ProveSubtree(ref.N, start, end, hr)
	if err != nil {
		return tlog.Hash{}, err
	}
	if err := torchwood.CheckSubtree(proof, ref.N, ref.Hash, start, end, h); err != nil {
		return tlog.Hash{}, err
	}
	return h, nil
}

// referenceCheckpoint fetches and verifies the checkpoints the policy needs
// and returns the smallest, after checking every larger one is consistent
// with it (Section 7.4). With no mirrors it is the CA's own checkpoint.
func referenceCheckpoint(ctx context.Context, p *Policy, origin string, caVerifier *torchwood.CosignatureVerifier, caFetcher *torchwood.TileFetcher) (*checkpoint, error) {
	if len(p.Mirrors) == 0 {
		return fetchCheckpoint(ctx, caFetcher, "CA", origin, caVerifier)
	}
	var cps []*checkpoint
	for _, m := range p.Mirrors {
		mv, err := m.Cosigner.Verifier()
		if err != nil {
			return nil, err
		}
		f, err := torchwood.NewTileFetcher(strings.TrimSuffix(m.URL, "/") + "/" + originHash(origin))
		if err != nil {
			return nil, err
		}
		cp, err := fetchCheckpoint(ctx, f, "mirror "+m.Cosigner.ID.String(), origin, caVerifier, mv)
		if err != nil {
			return nil, err
		}
		cps = append(cps, cp)
	}
	ref := cps[0]
	for _, cp := range cps[1:] {
		if cp.N < ref.N {
			ref = cp
		}
	}
	for _, cp := range cps {
		if cp == ref {
			continue
		}
		hr := torchwood.TileHashReaderWithContext(ctx, cp.Tree, cp.fetcher)
		proof, err := tlog.ProveTree(cp.N, ref.N, hr)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", cp.source, err)
		}
		if err := tlog.CheckTree(proof, cp.N, cp.Hash, ref.N, ref.Hash); err != nil {
			return nil, fmt.Errorf("%s is inconsistent with %s: %w", cp.source, ref.source, err)
		}
	}
	return ref, nil
}

// fetchCheckpoint reads a checkpoint and requires the origin and a valid
// signature from every verifier.
func fetchCheckpoint(ctx context.Context, f *torchwood.TileFetcher, source, origin string, verifiers ...*torchwood.CosignatureVerifier) (*checkpoint, error) {
	signed, err := f.ReadEndpoint(ctx, "checkpoint")
	if err != nil {
		return nil, fmt.Errorf("%s: fetching checkpoint: %w", source, err)
	}
	policies := []torchwood.Policy{torchwood.OriginPolicy(origin)}
	for _, v := range verifiers {
		policies = append(policies, torchwood.SingleVerifierPolicy(v))
	}
	c, _, err := torchwood.VerifyCheckpoint(signed, torchwood.ThresholdPolicy(len(policies), policies...))
	if err != nil {
		return nil, fmt.Errorf("%s: checkpoint: %w", source, err)
	}
	return &checkpoint{Checkpoint: c, fetcher: f, source: source}, nil
}

// originHash is the path component a tlog-mirror serves a log under.
func originHash(origin string) string {
	h := sha256.Sum256([]byte(origin))
	return hex.EncodeToString(h[:])
}
