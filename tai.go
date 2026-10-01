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

// Package mtcupdate vets a Merkle Tree Certificate CA's landmark subtrees for
// relying parties, per draft-ietf-plants-merkle-tree-certs-06, Section 7.4.
package mtcupdate

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// A TrustAnchorID is the binary representation of a trust anchor ID: the
// contents octets of a DER RELATIVE-OID (draft-ietf-tls-trust-anchor-ids-05,
// Section 4).
type TrustAnchorID []byte

// ParseTrustAnchorID parses the ASCII representation, e.g. "32473.1".
func ParseTrustAnchorID(s string) (TrustAnchorID, error) {
	if s == "" {
		return nil, errors.New("empty trust anchor ID")
	}
	var id TrustAnchorID
	for _, part := range strings.Split(s, ".") {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return nil, fmt.Errorf("trust anchor ID %q: bad component %q", s, part)
		}
		v, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("trust anchor ID %q: %v", s, err)
		}
		id = appendBase128(id, v)
	}
	if len(id) > 255 {
		return nil, fmt.Errorf("trust anchor ID %q is longer than 255 bytes", s)
	}
	return id, nil
}

func appendBase128(b []byte, v uint64) []byte {
	var tmp [10]byte
	i := len(tmp)
	for {
		i--
		tmp[i] = byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			break
		}
	}
	for j := i; j < len(tmp)-1; j++ {
		tmp[j] |= 0x80
	}
	return append(b, tmp[i:]...)
}

// Components returns the components of id, checking minimal encoding.
func (id TrustAnchorID) Components() ([]uint64, error) {
	var out []uint64
	rest := []byte(id)
	for len(rest) > 0 {
		if rest[0] == 0x80 {
			return nil, errors.New("trust anchor ID component is not minimally encoded")
		}
		var v uint64
		i := 0
		for {
			if i == len(rest) {
				return nil, errors.New("trust anchor ID component is truncated")
			}
			if v>>57 != 0 {
				return nil, errors.New("trust anchor ID component overflows")
			}
			v = v<<7 | uint64(rest[i]&0x7f)
			if rest[i]&0x80 == 0 {
				break
			}
			i++
		}
		out = append(out, v)
		rest = rest[i+1:]
	}
	return out, nil
}

// Validate checks that id is well formed.
func (id TrustAnchorID) Validate() error {
	if len(id) == 0 || len(id) > 255 {
		return errors.New("trust anchor ID length is not in 1..255")
	}
	_, err := id.Components()
	return err
}

// String returns the ASCII representation.
func (id TrustAnchorID) String() string {
	comps, err := id.Components()
	if err != nil {
		return fmt.Sprintf("<invalid trust anchor ID %x>", []byte(id))
	}
	parts := make([]string, len(comps))
	for i, c := range comps {
		parts[i] = strconv.FormatUint(c, 10)
	}
	return strings.Join(parts, ".")
}

// Child returns id with components appended.
func (id TrustAnchorID) Child(components ...uint64) TrustAnchorID {
	out := append(TrustAnchorID(nil), id...)
	for _, c := range components {
		out = appendBase128(out, c)
	}
	return out
}

// OriginString is the checkpoint origin and cosigner name form of id
// (draft-ietf-plants-merkle-tree-certs-06, Section 5.3.1).
func (id TrustAnchorID) OriginString() string {
	return "oid/1.3.6.1.4.1." + id.String()
}

// LogID returns the ID of issuance log logNumber of CA caID (Section 5.2).
func LogID(caID TrustAnchorID, logNumber uint16) TrustAnchorID {
	return caID.Child(0, uint64(logNumber))
}
