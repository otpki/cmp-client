package cmpclient

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/otpki/iogo/crypto/x509"

	"github.com/otpki/otpki-pkg/crmf"
	"github.com/otpki/otpki-pkg/pkiutil"

	cmp "github.com/otpki/otpki-pkg/cmp"
)

func buildCertRequest(
	subjectDER []byte,
	spki pkiutil.SubjectPublicKeyInfo,
	certReqID int,
	extensions []pkix.Extension,
) (crmf.CertRequest, []byte, error) {
	certReq := crmf.CertRequest{
		CertReqID: certReqID,
		CertTemplate: crmf.CertTemplate{
			Version: 2,
			Subject: asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        5,
				IsCompound: true,
				Bytes:      subjectDER,
			},
			PublicKey:  spki,
			Extensions: extensions,
		},
	}

	certReqDER, err := asn1.Marshal(certReq)
	if err != nil {
		return crmf.CertRequest{}, nil, fmt.Errorf("marshal CertRequest: %w", err)
	}

	return certReq, certReqDER, nil
}

func buildCertReqMsg(
	certReq crmf.CertRequest,
	popo asn1.RawValue,
) crmf.CertReqMsg {
	msg := crmf.CertReqMsg{
		CertReq: certReq,
	}

	if len(popo.FullBytes) != 0 || len(popo.Bytes) != 0 {
		msg.Popo = popo
	}

	return msg
}

func buildIRCertReqMessages(req IRRequest) (crmf.CertReqMessages, error) {
	entries := req.Requests
	if len(entries) == 0 {
		entries = []IRRequestEntry{{
			CertReqID:  0,
			Subject:    req.Subject,
			PublicKey:  req.PublicKey,
			SignerKey:  req.SignerKey,
			Extensions: req.Extensions,
		}}
	}

	msgs := make(crmf.CertReqMessages, 0, len(entries))
	seen := make(map[int]struct{}, len(entries))
	for i, entry := range entries {
		if entry.SignerKey == nil {
			return nil, fmt.Errorf("missing IR signer key for request %d", i)
		}

		spki, err := requestPublicKey(entry.PublicKey, entry.SignerKey)
		if err != nil {
			return nil, err
		}
		subjectDER, err := asn1.Marshal(entry.Subject.ToRDNSequence())
		if err != nil {
			return nil, fmt.Errorf("marshal subject for request %d: %w", i, err)
		}

		certReqID := entry.CertReqID
		if certReqID < 0 {
			return nil, fmt.Errorf("negative certReqID %d", certReqID)
		}
		if _, ok := seen[certReqID]; ok {
			return nil, fmt.Errorf("duplicate IR certReqID %d", certReqID)
		}
		seen[certReqID] = struct{}{}

		certReq, certReqDER, err := buildCertRequest(subjectDER, spki, certReqID, entry.Extensions)
		if err != nil {
			return nil, err
		}

		popo, err := crmf.BuildSignaturePOP(certReqDER, entry.SignerKey, nil)
		if err != nil {
			return nil, fmt.Errorf("build IR POP for request %d: %w", i, err)
		}

		crmMsg := buildCertReqMsg(certReq, popo)

		msgs = append(msgs, crmMsg)
	}

	return msgs, nil
}

func BuildIRMessage(req IRRequest, random io.Reader) (*cmp.PKIMessage, error) {
	if random == nil {
		random = rand.Reader
	}
	tx, err := randomBytes(req.TransactionID, random)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(req.SenderNonce, random)
	if err != nil {
		return nil, err
	}
	crmMsgs, err := buildIRCertReqMessages(req)
	if err != nil {
		return nil, err
	}

	msg := &cmp.PKIMessage{
		Header: cmp.PKIHeader{
			Pvno:          2,
			Sender:        req.Sender,
			Recipient:     req.Recipient,
			SenderKID:     cloneBytes(req.SenderKID),
			TransactionID: tx,
			SenderNonce:   nonce,
		},
		Body: cmp.PKIBody{
			Type:  cmp.BodyTypeIR,
			Value: crmMsgs,
		},
	}

	return msg, nil
}

func buildCRMFCertReqMessages(req CRRequest, bodyType cmp.PKIBodyType) (crmf.CertReqMessages, error) {
	entries := req.Requests
	if len(entries) == 0 {
		entries = []CRMFRequestEntry{{
			CertReqID:    0,
			Subject:      req.Subject,
			PublicKey:    req.PublicKey,
			POPSignerKey: req.POPSignerKey,
			Extensions:   req.Extensions,
		}}
	}

	msgs := make(crmf.CertReqMessages, 0, len(entries))
	seen := make(map[int]struct{}, len(entries))
	for i, entry := range entries {
		if entry.POPSignerKey == nil {
			return nil, fmt.Errorf("missing %s POP signer key for request %d", bodyType, i)
		}

		spki, err := requestPublicKey(entry.PublicKey, entry.POPSignerKey)
		if err != nil {
			return nil, err
		}
		subjectDER, err := asn1.Marshal(entry.Subject.ToRDNSequence())
		if err != nil {
			return nil, fmt.Errorf("marshal subject for request %d: %w", i, err)
		}

		certReqID := entry.CertReqID
		if certReqID < 0 {
			return nil, fmt.Errorf("negative certReqID %d", certReqID)
		}
		if _, ok := seen[certReqID]; ok {
			return nil, fmt.Errorf("duplicate %s certReqID %d", bodyType, certReqID)
		}
		seen[certReqID] = struct{}{}

		certReq, certReqDER, err := buildCertRequest(subjectDER, spki, certReqID, entry.Extensions)
		if err != nil {
			return nil, err
		}

		popo, err := crmf.BuildSignaturePOP(certReqDER, entry.POPSignerKey, nil)
		if err != nil {
			return nil, fmt.Errorf("build %s POP for request %d: %w", bodyType, i, err)
		}

		crmMsg := buildCertReqMsg(certReq, popo)

		msgs = append(msgs, crmMsg)
	}

	return msgs, nil
}

func buildCRMFMessage(bodyType cmp.PKIBodyType, req CRRequest, random io.Reader) (*cmp.PKIMessage, error) {
	if random == nil {
		random = rand.Reader
	}
	tx, err := randomBytes(req.TransactionID, random)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(req.SenderNonce, random)
	if err != nil {
		return nil, err
	}
	if req.SignerKey == nil {
		return nil, fmt.Errorf("missing %s signer key", bodyType)
	}
	crmMsgs, err := buildCRMFCertReqMessages(req, bodyType)
	if err != nil {
		return nil, err
	}

	msg := &cmp.PKIMessage{
		Header: cmp.PKIHeader{
			Pvno:          2,
			Sender:        req.Sender,
			Recipient:     req.Recipient,
			SenderKID:     cloneBytes(req.SenderKID),
			RecipKID:      cloneBytes(req.RecipKID),
			TransactionID: tx,
			SenderNonce:   nonce,
			RecipNonce:    cloneBytes(req.RecipNonce),
		},
		Body: cmp.PKIBody{
			Type:  bodyType,
			Value: crmMsgs,
		},
	}

	for _, c := range req.ExtraCerts {
		if c != nil {
			msg.ExtraCerts = append(msg.ExtraCerts, cmp.CMPCertificate{
				Raw:         c.Raw,
				Certificate: c,
			})
		}
	}

	return msg, nil
}

func BuildCRMessage(req CRRequest, random io.Reader) (*cmp.PKIMessage, error) {
	return buildCRMFMessage(cmp.BodyTypeCR, req, random)
}

func BuildKURMessage(req KURRequest, random io.Reader) (*cmp.PKIMessage, error) {
	return buildCRMFMessage(cmp.BodyTypeKUR, req, random)
}

func BuildP10CRMessage(req P10CRRequest, random io.Reader) (*cmp.PKIMessage, error) {
	if random == nil {
		random = rand.Reader
	}
	tx, err := randomBytes(req.TransactionID, random)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(req.SenderNonce, random)
	if err != nil {
		return nil, err
	}
	if req.SignerKey == nil {
		return nil, fmt.Errorf("missing p10cr signer key")
	}
	if len(req.CSRDER) == 0 {
		return nil, fmt.Errorf("missing p10cr csr")
	}

	csr, err := x509.ParseCertificateRequest(req.CSRDER)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR proof of possession: %w", err)
	}

	msg := &cmp.PKIMessage{
		Header: cmp.PKIHeader{
			Pvno:          2,
			Sender:        req.Sender,
			Recipient:     req.Recipient,
			SenderKID:     cloneBytes(req.SenderKID),
			RecipKID:      cloneBytes(req.RecipKID),
			TransactionID: tx,
			SenderNonce:   nonce,
			RecipNonce:    cloneBytes(req.RecipNonce),
		},
		Body: cmp.PKIBody{
			Type:  cmp.BodyTypeP10CR,
			Value: append([]byte(nil), req.CSRDER...),
		},
	}

	for _, c := range req.ExtraCerts {
		if c != nil {
			msg.ExtraCerts = append(msg.ExtraCerts, cmp.CMPCertificate{
				Raw:         c.Raw,
				Certificate: c,
			})
		}
	}

	return msg, nil
}

func requestPublicKey(spki pkiutil.SubjectPublicKeyInfo, signer crypto.Signer) (pkiutil.SubjectPublicKeyInfo, error) {
	derived, err := pkiutil.SubjectPublicKeyInfoFromPublicKey(signer.Public())
	if err != nil {
		return derived, err
	}
	if len(spki.Algorithm.Algorithm) == 0 {
		return derived, nil
	}
	actual, err := asn1.Marshal(spki)
	if err != nil {
		return derived, err
	}
	expected, err := asn1.Marshal(derived)
	if err != nil {
		return derived, err
	}
	if !bytes.Equal(actual, expected) {
		return derived, fmt.Errorf("request public key does not match POP signer")
	}
	return spki, nil
}
