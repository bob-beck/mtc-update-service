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
	"crypto/mldsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"filippo.io/torchwood"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Both the draft's experimental OIDs (Cloudflare's 44363.47 arc) and the
// IANA-assigned ones are accepted.
var (
	oidRDNATrustAnchorID     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 3}
	oidRDNATrustAnchorIDIANA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}
	oidMTCCASHA256           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 4}
	oidMTCCASHA256IANA       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 38}
	// oidMTCTlogPrefixURL is id-mtcTlogPrefixURL from c2sp.org/mtc-tlog.
	oidMTCTlogPrefixURL = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 64829, 2, 1}
)

var tagRelativeOID = cbasn1.Tag(13)

// A CA is what the relying party is configured with for a Merkle Tree CA,
// read from its certificate (draft-ietf-plants-merkle-tree-certs-06,
// Sections 5.5 and 7.1).
type CA struct {
	ID        TrustAnchorID
	Key       *mldsa.PublicKey
	MinSerial uint64
	MaxSerial uint64
	PrefixURL string
}

// A Cosigner is a cosigner's ID and ML-DSA-44 key (Section 5.3).
type Cosigner struct {
	ID  TrustAnchorID
	Key *mldsa.PublicKey
}

// Verifier returns the cosigner as a checkpoint signature verifier.
func (c *Cosigner) Verifier() (*torchwood.CosignatureVerifier, error) {
	return torchwood.NewCosignatureVerifierFromKey(c.ID.OriginString(), c.Key)
}

// ParseCACertificatePEM parses the first CERTIFICATE in data as an MTC CA
// certificate.
func ParseCACertificatePEM(data []byte) (*CA, error) {
	ders, err := pemCertificates(data)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, err
	}
	id, key, err := trustAnchorIDAndKey(cert)
	if err != nil {
		return nil, fmt.Errorf("CA certificate: %w", err)
	}
	ca := &CA{ID: id, Key: key}
	found := false
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidMTCCASHA256) || ext.Id.Equal(oidMTCCASHA256IANA):
			if found {
				return nil, errors.New("CA certificate has two MTC CA extensions")
			}
			if !ext.Critical {
				return nil, errors.New("MTC CA extension is not critical")
			}
			v := cryptobyte.String(ext.Value)
			var seq, alg cryptobyte.String
			if !v.ReadASN1(&seq, cbasn1.SEQUENCE) || !v.Empty() ||
				!seq.ReadASN1(&alg, cbasn1.SEQUENCE) ||
				!seq.ReadASN1Integer(&ca.MinSerial) ||
				!seq.ReadASN1Integer(&ca.MaxSerial) || !seq.Empty() {
				return nil, errors.New("malformed MTC CA extension")
			}
			if ca.MinSerial < 1<<48 || ca.MaxSerial < ca.MinSerial {
				return nil, errors.New("invalid serial range in MTC CA extension")
			}
			found = true
		case ext.Id.Equal(oidMTCTlogPrefixURL):
			v := cryptobyte.String(ext.Value)
			var s cryptobyte.String
			if !v.ReadASN1(&s, cbasn1.IA5String) || !v.Empty() {
				return nil, errors.New("malformed mtc-tlog prefix URL extension")
			}
			ca.PrefixURL = string(s)
		}
	}
	if !found {
		return nil, errors.New("certificate has no MTC CA extension")
	}
	return ca, nil
}

// ParseCosignerCertificatesPEM parses every CERTIFICATE in data as a
// cosigner certificate: the CA certificate's unsigned shape with the cosigner
// ID as subject and the cosigner key, and no MTC CA extension. The draft
// does not define this form; it is what OpenSSL's
// OSSL_MTC_COSIGNER_parse_certificates() reads.
func ParseCosignerCertificatesPEM(data []byte) ([]*Cosigner, error) {
	ders, err := pemCertificates(data)
	if err != nil {
		return nil, err
	}
	var out []*Cosigner
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidMTCCASHA256) || ext.Id.Equal(oidMTCCASHA256IANA) {
				return nil, errors.New("cosigner certificate carries the MTC CA extension")
			}
		}
		id, key, err := trustAnchorIDAndKey(cert)
		if err != nil {
			return nil, fmt.Errorf("cosigner certificate: %w", err)
		}
		out = append(out, &Cosigner{ID: id, Key: key})
	}
	return out, nil
}

func pemCertificates(data []byte) ([][]byte, error) {
	var out [][]byte
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			out = append(out, b.Bytes)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM CERTIFICATE found")
	}
	return out, nil
}

// trustAnchorIDAndKey returns the trust anchor ID in cert's subject (a
// single id-rdna-trustAnchorID attribute holding a RELATIVE-OID, Section
// 5.1) and its ML-DSA-44 key.
func trustAnchorIDAndKey(cert *x509.Certificate) (TrustAnchorID, *mldsa.PublicKey, error) {
	s := cryptobyte.String(cert.RawSubject)
	var dn, rdn, attr, val cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&dn, cbasn1.SEQUENCE) || !s.Empty() ||
		!dn.ReadASN1(&rdn, cbasn1.SET) || !dn.Empty() ||
		!rdn.ReadASN1(&attr, cbasn1.SEQUENCE) || !rdn.Empty() ||
		!attr.ReadASN1ObjectIdentifier(&oid) ||
		!attr.ReadASN1(&val, tagRelativeOID) || !attr.Empty() {
		return nil, nil, errors.New("subject is not a single trust anchor ID attribute")
	}
	if !oid.Equal(oidRDNATrustAnchorID) && !oid.Equal(oidRDNATrustAnchorIDIANA) {
		return nil, nil, errors.New("subject attribute is not id-rdna-trustAnchorID")
	}
	id := TrustAnchorID(append([]byte(nil), val...))
	if err := id.Validate(); err != nil {
		return nil, nil, err
	}
	key, ok := cert.PublicKey.(*mldsa.PublicKey)
	if !ok || key.Parameters() != mldsa.MLDSA44() {
		return nil, nil, errors.New("key is not ML-DSA-44")
	}
	return id, key, nil
}
