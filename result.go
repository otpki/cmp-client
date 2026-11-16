package cmpclient

import (
	"bytes"
	"fmt"

	"github.com/otpki/iogo/crypto/x509"
	"github.com/otpki/otpki-pkg/cmp"
	"github.com/otpki/otpki-pkg/crmf"
)

// ProtocolError is an authenticated CMP error or rejected certificate request.
// Status preserves the protocol's failInfo and statusString fields.
type ProtocolError struct {
	Operation string
	CertReqID int
	Status    cmp.PKIStatusInfo
	Code      int
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("CMP %s rejected request %d: status=%d errorCode=%d failInfo=%x", e.Operation, e.CertReqID, e.Status.Status, e.Code, e.Status.FailInfo.Bytes)
}

func expectedRequestIDs(msg *cmp.PKIMessage) map[int]bool {
	ids := make(map[int]bool)
	if requests, ok := msg.Body.Value.(crmf.CertReqMessages); ok {
		for _, request := range requests {
			ids[request.CertReq.CertReqID] = true
		}
	} else {
		// Existing OTPKI deployments use 0 for PKCS#10; RFC 4210 uses -1.
		ids[0] = true
	}
	return ids
}

func checkResultIDs(result *enrollmentResult, expected map[int]bool) error {
	seen := make(map[int]bool)
	for _, id := range result.PendingCertReqIDs {
		if !expected[id] || seen[id] {
			return fmt.Errorf("unexpected or duplicate CMP request ID %d", id)
		}
		seen[id] = true
	}
	for _, response := range result.Responses {
		if !expected[response.CertReqID] || seen[response.CertReqID] {
			return fmt.Errorf("unexpected or duplicate CMP request ID %d", response.CertReqID)
		}
		seen[response.CertReqID] = true
	}
	return nil
}

func checkIssuedKeys(request *cmp.PKIMessage, result *enrollmentResult) error {
	expected := make(map[int][]byte)
	switch body := request.Body.Value.(type) {
	case crmf.CertReqMessages:
		for _, crm := range body {
			key, err := crmf.PublicKey(crm.CertReq)
			if err != nil {
				return err
			}
			der, err := x509.MarshalPKIXPublicKey(key)
			if err != nil {
				return err
			}
			expected[crm.CertReq.CertReqID] = der
		}
	case []byte:
		csr, err := x509.ParseCertificateRequest(body)
		if err != nil {
			return err
		}
		expected[0] = csr.RawSubjectPublicKeyInfo
		expected[-1] = csr.RawSubjectPublicKeyInfo
	}
	for _, response := range result.Responses {
		if response.Certificate == nil || !bytes.Equal(expected[response.CertReqID], response.Certificate.RawSubjectPublicKeyInfo) {
			return fmt.Errorf("issued certificate key does not match request %d", response.CertReqID)
		}
	}
	return nil
}
