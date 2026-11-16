package cmpclient

import (
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/otpki/otpki-pkg/pkiutil"

	cmp "github.com/otpki/otpki-pkg/cmp"
	"github.com/otpki/otpki-pkg/oids"
)

func algSHA256() pkiutil.AlgorithmIdentifier {
	return pkiutil.AlgorithmIdentifier{
		Algorithm: oids.OidASN1SHA256,
		Parameters: asn1.RawValue{
			Tag: 5,
		},
	}
}

func algHMACSHA256() pkiutil.AlgorithmIdentifier {
	return pkiutil.AlgorithmIdentifier{
		Algorithm: oids.OidHMACWithSHA256,
		Parameters: asn1.RawValue{
			Tag: 5,
		},
	}
}

func ApplyPBMProtection(msg *cmp.PKIMessage, secret []byte, random io.Reader) error {
	if msg == nil {
		return fmt.Errorf("nil message")
	}
	if len(secret) == 0 {
		return fmt.Errorf("empty PBM secret")
	}

	if random == nil {
		random = rand.Reader
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(random, salt); err != nil {
		return fmt.Errorf("read PBM salt: %w", err)
	}
	pbm := cmp.PBMParameter{
		Salt:           salt,
		OWF:            algSHA256(),
		IterationCount: 1000,
		MAC:            algHMACSHA256(),
	}

	pbmDER, err := asn1.Marshal(pbm)
	if err != nil {
		return fmt.Errorf("marshal PBMParameter: %w", err)
	}

	alg := pkiutil.AlgorithmIdentifier{
		Algorithm: oids.OidPasswordBasedMAC,
		Parameters: asn1.RawValue{
			FullBytes: pbmDER,
		},
	}

	if err := msg.Header.SetProtectionAlg(alg); err != nil {
		return fmt.Errorf("set protectionAlg: %w", err)
	}

	protectedDER, err := cmp.MarshalProtectedPart(msg)
	if err != nil {
		return fmt.Errorf("marshal protected part: %w", err)
	}

	macValue, err := computePBM(secret, protectedDER, pbm)
	if err != nil {
		return err
	}

	msg.Protection = &asn1.BitString{
		Bytes:     macValue,
		BitLength: len(macValue) * 8,
	}

	return nil
}

func computePBM(secret, data []byte, p cmp.PBMParameter) ([]byte, error) {
	if !p.OWF.Algorithm.Equal(oids.OidASN1SHA256) {
		return nil, fmt.Errorf("unsupported OWF")
	}
	if !p.MAC.Algorithm.Equal(oids.OidHMACWithSHA256) {
		return nil, fmt.Errorf("unsupported MAC")
	}

	return cmp.ComputePBM(secret, data, p, false)
}
