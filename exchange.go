package cmpclient

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/otpki/iogo/crypto/x509"
	"github.com/otpki/otpki-pkg/cmp"
)

// Protection selects either legacy PasswordBasedMac or a certificate signature.
// Never supply both. PBMAC1 is not implemented.
type Protection struct {
	SharedSecret []byte
	SignerCert   *x509.Certificate
	SignerKey    crypto.Signer
}

// Exchange protects a caller-built message and verifies the response. It can be
// used for confirmation, revocation, general messages, or single-step polling.
// The message is updated with its protection algorithm, signature/MAC and certs.
// Protocol status processing remains with the caller; SendRaw bypasses protection
// verification entirely for tests that deliberately violate the protocol.
func (c *Client) Exchange(ctx context.Context, endpoint string, msg *cmp.PKIMessage, protection Protection) (*cmp.PKIMessage, error) {
	if c == nil || msg == nil {
		return nil, fmt.Errorf("missing client or message")
	}
	password := len(protection.SharedSecret) > 0
	signature := protection.SignerCert != nil || protection.SignerKey != nil
	if password == signature {
		return nil, fmt.Errorf("select exactly one CMP protection method")
	}
	if signature && c.ServerCertificate == nil {
		return nil, fmt.Errorf("signature exchange requires ServerCertificate")
	}
	random := c.Rand
	if random == nil {
		random = rand.Reader
	}
	protect := func(msg *cmp.PKIMessage) error {
		if password {
			return ApplyPBMProtection(msg, protection.SharedSecret, random)
		}
		return ApplySignatureProtection(msg, protection.SignerCert, protection.SignerKey)
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = defaultHTTPClient()
	}
	raw, err := c.sendProtectedMessage(ctx, hc, endpoint, msg, protect)
	if err != nil {
		return nil, err
	}
	return c.VerifyResponse(msg, raw, protection.SharedSecret)
}

// DirectoryName encodes a subject/issuer as a CMP directoryName GeneralName.
func DirectoryName(name pkix.Name) (asn1.RawValue, error) {
	der, err := asn1.Marshal(name.ToRDNSequence())
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: der}, nil
}
