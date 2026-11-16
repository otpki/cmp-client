package cmpclient

import (
	"encoding/asn1"
	"fmt"

	"github.com/otpki/otpki-pkg/pkiutil"

	"github.com/otpki/iogo/crypto/x509"

	cmp "github.com/otpki/otpki-pkg/cmp"
)

func extractIssuedCert(resp cmp.CertResponse) (*x509.Certificate, error) {
	rv := resp.CertifiedKeyPair.CertOrEncCert

	// Direct parse attempts first.
	for _, b := range [][]byte{rv.FullBytes, rv.Bytes} {
		if len(b) == 0 {
			continue
		}
		if cert, err := x509.ParseCertificate(b); err == nil {
			return cert, nil
		}
		if cert, err := x509.ParseCertificate(pkiutil.EnsureDERSequence(b)); err == nil {
			return cert, nil
		}
	}

	// CMP CertOrEncCert certificate choice: [0] wrapped certificate
	if rv.Class == asn1.ClassContextSpecific && rv.Tag == 0 {
		if len(rv.Bytes) != 0 {
			if cert, err := x509.ParseCertificate(rv.Bytes); err == nil {
				return cert, nil
			}
			if cert, err := x509.ParseCertificate(pkiutil.EnsureDERSequence(rv.Bytes)); err == nil {
				return cert, nil
			}
		}
	}

	// One-level unwrap fallback.
	for _, b := range [][]byte{rv.FullBytes, rv.Bytes} {
		if len(b) == 0 {
			continue
		}
		var inner asn1.RawValue
		if _, err := asn1.Unmarshal(b, &inner); err == nil {
			for _, ib := range [][]byte{inner.FullBytes, inner.Bytes} {
				if len(ib) == 0 {
					continue
				}
				if cert, err := x509.ParseCertificate(ib); err == nil {
					return cert, nil
				}
				if cert, err := x509.ParseCertificate(pkiutil.EnsureDERSequence(ib)); err == nil {
					return cert, nil
				}
			}
		}
	}

	return nil, fmt.Errorf(
		"no certificate in response (class=%d tag=%d full=%d bytes=%d)",
		rv.Class, rv.Tag, len(rv.FullBytes), len(rv.Bytes),
	)
}

func parseCAPubs(raws []asn1.RawValue) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(raws))

	for i, rv := range raws {
		if len(rv.FullBytes) == 0 {
			return nil, fmt.Errorf("caPubs[%d]: empty", i)
		}

		cert, err := x509.ParseCertificate(rv.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("caPubs[%d]: %w", i, err)
		}

		out = append(out, cert)
	}

	return out, nil
}
