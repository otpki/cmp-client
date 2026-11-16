package cmpclient

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/otpki/otpki-pkg/cmp"

	"github.com/otpki/otpki-pkg/pkiutil"

	"github.com/otpki/iogo/crypto/x509"
)

type IRRequestEntry struct {
	CertReqID  int
	Subject    pkix.Name
	Extensions []pkix.Extension
	PublicKey  pkiutil.SubjectPublicKeyInfo
	SignerKey  crypto.Signer
}

// IRRequest represents an Initialization Request (IR) using PBM protection.
type IRRequest struct {
	URL string

	Sender    asn1.RawValue
	Recipient asn1.RawValue

	Subject    pkix.Name
	Extensions []pkix.Extension
	PublicKey  pkiutil.SubjectPublicKeyInfo

	// Key used for IR POP/signature over the CertRequest.
	SignerKey crypto.Signer

	SharedSecret []byte
	SenderKID    []byte

	TransactionID []byte
	SenderNonce   []byte

	Requests []IRRequestEntry
}

type EnrollmentResponseEntry struct {
	CertReqID   int
	Certificate *x509.Certificate
}

// IRResponse represents the result of an IR operation.
type IRResponse struct {
	Certificate  *x509.Certificate
	Certificates []*x509.Certificate
	Responses    []EnrollmentResponseEntry
	CAPubs       []*x509.Certificate
	RawResponse  []byte
	Message      *cmp.PKIMessage
}

type CRMFRequestEntry struct {
	CertReqID    int
	Subject      pkix.Name
	Extensions   []pkix.Extension
	PublicKey    pkiutil.SubjectPublicKeyInfo
	POPSignerKey crypto.Signer
}

// CRRequest represents a Certification Request (CR) using signature protection
// and signature-based proof-of-possession.
type CRRequest struct {
	URL string

	Sender    asn1.RawValue
	Recipient asn1.RawValue

	Subject    pkix.Name
	Extensions []pkix.Extension
	PublicKey  pkiutil.SubjectPublicKeyInfo

	SignerCert   *x509.Certificate
	SignerKey    crypto.Signer
	POPSignerKey crypto.Signer

	ExtraCerts []*x509.Certificate

	SenderKID     []byte
	RecipKID      []byte
	TransactionID []byte
	SenderNonce   []byte
	RecipNonce    []byte

	Requests []CRMFRequestEntry
}

// CRResponse represents the result of a CR operation.
type CRResponse struct {
	Certificate  *x509.Certificate
	Certificates []*x509.Certificate
	Responses    []EnrollmentResponseEntry
	CAPubs       []*x509.Certificate
	RawResponse  []byte
	Message      *cmp.PKIMessage
}

type (
	KURRequest  = CRRequest
	KURResponse = CRResponse
)

type P10CRRequest struct {
	URL string

	Sender    asn1.RawValue
	Recipient asn1.RawValue

	SignerCert *x509.Certificate
	SignerKey  crypto.Signer

	CSRDER []byte

	ExtraCerts []*x509.Certificate

	SenderKID     []byte
	RecipKID      []byte
	TransactionID []byte
	SenderNonce   []byte
	RecipNonce    []byte
}

type P10CRResponse = CRResponse
