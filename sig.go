package cmpclient

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/otpki/iogo/crypto/x509"

	cmp "github.com/otpki/otpki-pkg/cmp"
	"github.com/otpki/otpki-pkg/pkiutil"
)

// ApplySignatureProtection signs the ProtectedPart and sets msg.Protection
func ApplySignatureProtection(msg *cmp.PKIMessage, cert *x509.Certificate, key crypto.Signer) error {
	if msg == nil {
		return fmt.Errorf("nil message")
	}
	if cert == nil || key == nil {
		return fmt.Errorf("missing signer cert or key")
	}

	keyDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	certKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(keyDER, certKeyDER) {
		return fmt.Errorf("signer certificate and key do not match")
	}
	alg, hash, err := signatureAlgorithm(key)
	if err != nil {
		return err
	}

	if err := cmp.SignProtection(msg, key, alg, hash, rand.Reader); err != nil {
		return fmt.Errorf("sign protected part: %w", err)
	}

	// include signer cert (OpenSSL compatibility)
	msg.ExtraCerts = append(msg.ExtraCerts, cmp.CMPCertificate{
		Raw:         cert.Raw,
		Certificate: cert,
	})

	return nil
}

func signatureAlgorithm(key crypto.Signer) (pkiutil.AlgorithmIdentifier, crypto.Hash, error) {
	if key == nil {
		return pkiutil.AlgorithmIdentifier{}, 0, fmt.Errorf("missing signer key")
	}

	alg, hash, err := pkiutil.SignerAlgorithmFromPublicKey(key.Public())
	if err != nil {
		return pkiutil.AlgorithmIdentifier{}, 0, fmt.Errorf("resolve signer algorithm: %w", err)
	}

	return pkiutil.AlgorithmIdentifier{
		Algorithm:  alg.Algorithm,
		Parameters: alg.Parameters,
	}, hash, nil
}
