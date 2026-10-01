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
	"encoding/hex"
	"testing"
	"time"
)

func TestTrustAnchorID(t *testing.T) {
	// draft-ietf-tls-trust-anchor-ids-05, Section 4 and Appendix A.
	for _, tc := range []struct{ text, hex string }{
		{"32473.1", "81fd5901"},
		{"32473.456.99999", "81fd598348868d1f"},
		{"32473.456.18446744073709551615", "81fd59834881ffffffffffffffff7f"},
	} {
		id, err := ParseTrustAnchorID(tc.text)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(id) != tc.hex || id.String() != tc.text {
			t.Errorf("%s: %x %s", tc.text, []byte(id), id)
		}
	}
	for _, bad := range []string{"8081fd597b8615", "81fd597b8695", "81fd5982808080808080808000"} {
		b, _ := hex.DecodeString(bad)
		if err := TrustAnchorID(b).Validate(); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	ca := TrustAnchorID{0x81, 0xfd, 0x59, 0x64}
	if got := LogID(ca, 8).Child(1, 42).String(); got != "32473.100.0.8.1.42" {
		t.Error(got)
	}
	if got := (TrustAnchorID{0x81, 0xfd, 0x59, 0x01}).OriginString(); got != "oid/1.3.6.1.4.1.32473.1" {
		t.Error(got)
	}
}

func TestLandmarkSubtrees(t *testing.T) {
	// draft-ietf-plants-merkle-tree-certs-06, Section 4.5.1: [5, 13) is
	// covered by [4, 8) and [8, 13).
	sts, err := LandmarkSubtrees(5, 13)
	if err != nil {
		t.Fatal(err)
	}
	if len(sts) != 2 || sts[0] != (Subtree{4, 8}) || sts[1] != (Subtree{8, 13}) {
		t.Error(sts)
	}
	if sts, _ := LandmarkSubtrees(0, 0); len(sts) != 0 {
		t.Error(sts)
	}
	if _, err := LandmarkSubtrees(5, 4); err == nil {
		t.Error("decreasing sizes accepted")
	}
}

func TestParseLandmarks(t *testing.T) {
	now := time.Unix(1000, 0)
	ls, err := ParseLandmarks([]byte("3\n30 1200\n20 1100\n10 900\n"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 3 || ls[0] != (Landmark{3, 30, 1200}) || ls[2] != (Landmark{1, 10, 900}) || ls[2].Active(now) || !ls[1].Active(now) {
		t.Error(ls)
	}
	for _, bad := range []string{
		"3\n30 1200\n20 1100\n",         // no expired landmark
		"3\n30 1200\n20 1100\n10 900",   // no final newline
		"3\n30 1200\n40 1100\n10 900\n", // sizes not decreasing
		"3\n30 1200\n20 1300\n10 900\n", // expiries increase
		"3\n30 1200\n20 900\n10 900\n",  // lines after the expired one
		"1\n30 1200\n20 1100\n10 900\n", // more lines than landmarks
		"3\n30 1200\n020 1100\n10 900\n",
	} {
		if _, err := ParseLandmarks([]byte(bad), now); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
