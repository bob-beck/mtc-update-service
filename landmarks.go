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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"filippo.io/torchwood"
)

// MaxLogEntries is the largest tree size an issuance log can reach
// (draft-ietf-plants-merkle-tree-certs-06, Section 5.2).
const MaxLogEntries = 1<<48 - 1

// A Landmark is one entry of a CA's landmark sequence (Section 6.4.1).
type Landmark struct {
	Number   uint64
	TreeSize uint64
	Expiry   int64 // POSIX seconds
}

// Active reports whether l is active at now (Section 6.4.1).
func (l Landmark) Active(now time.Time) bool {
	return l.Number != 0 && now.Unix() <= l.Expiry
}

// A Subtree is [Start, End) of an issuance log.
type Subtree struct {
	Start, End uint64
}

// LandmarkSubtrees returns the two subtrees of a landmark with tree size
// treeSize whose predecessor has tree size prevTreeSize (Sections 4.5.1 and
// 6.4.1). Either may be empty.
func LandmarkSubtrees(prevTreeSize, treeSize uint64) ([]Subtree, error) {
	if prevTreeSize > treeSize || treeSize > MaxLogEntries {
		return nil, errors.New("invalid landmark tree sizes")
	}
	leftStart, mid, err := torchwood.CoverInterval(int64(prevTreeSize), int64(treeSize))
	if err != nil {
		return nil, err
	}
	var out []Subtree
	for _, s := range []Subtree{{uint64(leftStart), uint64(mid)}, {uint64(mid), treeSize}} {
		if s.Start != s.End {
			out = append(out, s)
		}
	}
	return out, nil
}

// ParseLandmarks parses a published landmark list (Section 6.4.3) and
// returns its landmarks newest first, ending with the first one that is
// expired at now. It rejects anything that does not conform exactly.
func ParseLandmarks(data []byte, now time.Time) ([]Landmark, error) {
	text := string(data)
	if !strings.HasSuffix(text, "\n") {
		return nil, errors.New("landmarks: missing final newline")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	latest, err := parseDecimal(lines[0])
	if err != nil || latest > MaxLogEntries {
		return nil, fmt.Errorf("landmarks: bad latest landmark %q", lines[0])
	}
	if uint64(len(lines)-1) > latest {
		return nil, errors.New("landmarks: more lines than landmarks")
	}
	var out []Landmark
	for i, line := range lines[1:] {
		sizeText, expiryText, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("landmarks: malformed line %q", line)
		}
		size, err1 := parseDecimal(sizeText)
		expiry, err2 := parseDecimal(expiryText)
		if err1 != nil || err2 != nil || size > MaxLogEntries || expiry > 1<<63-1 {
			return nil, fmt.Errorf("landmarks: malformed line %q", line)
		}
		l := Landmark{Number: latest - uint64(i), TreeSize: size, Expiry: int64(expiry)}
		if n := len(out); n > 0 {
			if l.TreeSize >= out[n-1].TreeSize {
				return nil, errors.New("landmarks: tree sizes do not strictly decrease")
			}
			if l.Expiry > out[n-1].Expiry {
				return nil, errors.New("landmarks: expiries increase")
			}
		}
		out = append(out, l)
		if !l.Active(now) {
			return out, nil
		}
	}
	return nil, errors.New("landmarks: no expired landmark")
}

func parseDecimal(s string) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("bad number %q", s)
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("bad number %q", s)
		}
	}
	return strconv.ParseUint(s, 10, 64)
}
