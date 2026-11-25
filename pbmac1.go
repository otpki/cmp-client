package cmpclient

import (
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/otpki/otpki-pkg/cmp"
	"github.com/otpki/otpki-pkg/oids"
	"github.com/otpki/otpki-pkg/pkiutil"
)

// ApplyPBMAC1Protection protects a message using PBKDF2 and HMAC-SHA-256.
func ApplyPBMAC1Protection(msg *cmp.PKIMessage, secret []byte, random io.Reader) error {
	if msg == nil || len(secret) == 0 {
		return fmt.Errorf("PBMAC1 protection requires a message and shared secret")
	}
	if random == nil {
		random = rand.Reader
	}
	parameters, err := cmp.NewPBMAC1Parameters(random)
	if err != nil {
		return err
	}
	der, err := asn1.Marshal(parameters)
	if err != nil {
		return fmt.Errorf("marshal PBMAC1 parameters: %w", err)
	}
	if err := msg.Header.SetProtectionAlg(pkiutil.AlgorithmIdentifier{Algorithm: oids.OidPBMAC1, Parameters: asn1.RawValue{FullBytes: der}}); err != nil {
		return err
	}
	protected, err := cmp.MarshalProtectedPart(msg)
	if err != nil {
		return err
	}
	mac, err := cmp.ComputePBMAC1(secret, protected, parameters, false)
	if err != nil {
		return err
	}
	msg.Protection = &asn1.BitString{Bytes: mac, BitLength: len(mac) * 8}
	return nil
}
