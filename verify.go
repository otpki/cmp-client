package cmpclient

import (
	"bytes"
	"crypto/hmac"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/otpki/iogo/crypto/x509"

	"github.com/otpki/otpki-pkg/cmp"
	"github.com/otpki/otpki-pkg/oids"
	"github.com/otpki/otpki-pkg/pkiutil"
)

// VerifyResponse authenticates exact received wire bytes, then checks version,
// transaction ID, recipient nonce, and sender/recipient continuity. A configured
// ServerCertificate requires signature protection, even for PBM requests.
func (c *Client) VerifyResponse(request *cmp.PKIMessage, raw []byte, secret []byte) (*cmp.PKIMessage, error) {
	if c == nil || request == nil {
		return nil, fmt.Errorf("missing client or request")
	}
	var top asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &top)
	if err != nil || len(rest) != 0 || top.Class != asn1.ClassUniversal || top.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("CMP response must contain exactly one DER sequence")
	}
	response, _, _, err := cmp.DecodePKIMessage(raw)
	if err != nil {
		return nil, fmt.Errorf("decode CMP response: %w", err)
	}
	if response.Protection == nil || len(response.Protection.Bytes) == 0 || response.Protection.BitLength != len(response.Protection.Bytes)*8 {
		return nil, fmt.Errorf("CMP response is missing valid protection")
	}
	alg, present, err := response.Header.ParsedProtectionAlg()
	if err != nil || !present {
		return nil, fmt.Errorf("CMP response has no valid protection algorithm")
	}
	protected, err := cmp.ProtectedPartFromWire(response)
	if err != nil {
		return nil, fmt.Errorf("CMP response protected part: %w", err)
	}
	if c.ServerCertificate != nil {
		cert := c.ServerCertificate
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return nil, fmt.Errorf("pinned CMP signer certificate is outside its validity period")
		}
		if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return nil, fmt.Errorf("pinned CMP signer certificate does not permit digital signatures")
		}
		sigAlg, err := pkiutil.SigAlgFromAlgID(alg.Algorithm, &alg.Parameters)
		if err != nil {
			return nil, fmt.Errorf("CMP response signature algorithm: %w", err)
		}
		if err := pkiutil.VerifySignature(cert.PublicKey, sigAlg, protected, response.Protection.Bytes); err != nil {
			return nil, fmt.Errorf("CMP response signature: %w", err)
		}
	} else {
		if len(secret) == 0 || !alg.Algorithm.Equal(oids.OidPasswordBasedMAC) {
			return nil, fmt.Errorf("CMP response requires a pinned signer certificate or legacy PBM credentials")
		}
		var parameters cmp.PBMParameter
		rest, err := asn1.Unmarshal(alg.Parameters.FullBytes, &parameters)
		if err != nil || len(rest) != 0 {
			return nil, fmt.Errorf("invalid CMP response PBM parameters")
		}
		if len(parameters.Salt) < 8 || len(parameters.Salt) > 1024 {
			return nil, fmt.Errorf("invalid CMP response PBM salt length")
		}
		mac, err := cmp.ComputePBM(secret, protected, parameters, false)
		if err != nil {
			return nil, fmt.Errorf("CMP response PBM: %w", err)
		}
		if !hmac.Equal(mac, response.Protection.Bytes) {
			return nil, fmt.Errorf("CMP response PBM mismatch")
		}
	}
	h, r := response.Header, request.Header
	if h.Pvno != r.Pvno || (h.Pvno != 2 && h.Pvno != 3) {
		return nil, fmt.Errorf("CMP response version mismatch")
	}
	if len(r.TransactionID) == 0 || !bytes.Equal(h.TransactionID, r.TransactionID) {
		return nil, fmt.Errorf("CMP response transaction ID mismatch")
	}
	if len(r.SenderNonce) == 0 || !bytes.Equal(h.RecipNonce, r.SenderNonce) {
		return nil, fmt.Errorf("CMP response recipient nonce mismatch")
	}
	if len(h.SenderNonce) < 16 {
		return nil, fmt.Errorf("CMP response sender nonce too short")
	}
	for _, pair := range [][2]asn1.RawValue{{h.Recipient, r.Sender}, {h.Sender, r.Recipient}} {
		a, err := asn1.Marshal(pair[0])
		if err != nil {
			return nil, err
		}
		b, err := asn1.Marshal(pair[1])
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(a, b) {
			return nil, fmt.Errorf("CMP response sender/recipient mismatch")
		}
	}
	return response, nil
}
