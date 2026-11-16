package cmpclient

import (
	"fmt"
	"slices"

	cmp "github.com/otpki/otpki-pkg/cmp"
)

func parseEnrollmentResult(rawResp []byte, expectedBodyType cmp.PKIBodyType, op string) (*enrollmentResult, error) {
	respMsg, _, _, err := cmp.DecodePKIMessage(rawResp)
	if err != nil {
		return nil, fmt.Errorf("decode PKIMessage: %w", err)
	}

	if respMsg.Body.Type == cmp.BodyTypeError {
		status, ok := respMsg.Body.Value.(cmp.ErrorMsgContent)
		if !ok {
			return nil, fmt.Errorf("invalid CMP error response")
		}
		return nil, &ProtocolError{Operation: op, CertReqID: -1, Status: status.Status, Code: status.ErrorCode}
	}

	if respMsg.Body.Type == cmp.BodyTypePollRep {
		rep, ok := respMsg.Body.Value.(cmp.PollRepContent)
		if !ok {
			return nil, fmt.Errorf("pollRep: expected PollRepContent, got %T", respMsg.Body.Value)
		}
		if len(rep) == 0 {
			return nil, fmt.Errorf("pollRep: no responses")
		}
		pendingCertReqIDs := make([]int, 0, len(rep))
		checkAfter := rep[0].CheckAfter
		for _, pollRep := range rep {
			if pollRep.CheckAfter < 0 {
				return nil, fmt.Errorf("negative CMP checkAfter")
			}
			pendingCertReqIDs = append(pendingCertReqIDs, pollRep.CertReqID)
			if pollRep.CheckAfter > checkAfter {
				checkAfter = pollRep.CheckAfter
			}
		}
		return &enrollmentResult{
			Message:           respMsg,
			RawResponse:       rawResp,
			Pending:           true,
			CertReqID:         rep[0].CertReqID,
			PendingCertReqIDs: pendingCertReqIDs,
			CheckAfter:        checkAfter,
		}, nil
	}

	if respMsg.Body.Type != expectedBodyType {
		return nil, fmt.Errorf("unexpected response body type: %s", respMsg.Body.Type)
	}

	rep, ok := respMsg.Body.Value.(cmp.CertRepMessage)
	if !ok {
		return nil, fmt.Errorf("%s: expected CertRepMessage, got %T", expectedBodyType, respMsg.Body.Value)
	}

	if len(rep.Responses) == 0 {
		return nil, fmt.Errorf("%s: no responses", expectedBodyType)
	}

	caPubs, err := parseCAPubs(rep.CAPubs)
	if err != nil {
		return nil, err
	}

	result := &enrollmentResult{
		Message:     respMsg,
		CAPubs:      caPubs,
		RawResponse: rawResp,
	}

	for _, response := range rep.Responses {
		status := response.Status.Status
		switch status {
		case cmp.PKIStatusWaiting:
			result.Pending = true
			result.PendingCertReqIDs = append(result.PendingCertReqIDs, response.CertReqID)
			if result.CertReqID == 0 && len(result.PendingCertReqIDs) == 1 {
				result.CertReqID = response.CertReqID
			}
		case cmp.PKIStatusAccepted, cmp.PKIStatusGrantedWithMods:
			cert, err := extractIssuedCert(response)
			if err != nil {
				return nil, fmt.Errorf(
					"%s no certificate in response for certReqID %d (status=%d class=%d tag=%d full=%d bytes=%d)",
					op,
					response.CertReqID,
					status,
					response.CertifiedKeyPair.CertOrEncCert.Class,
					response.CertifiedKeyPair.CertOrEncCert.Tag,
					len(response.CertifiedKeyPair.CertOrEncCert.FullBytes),
					len(response.CertifiedKeyPair.CertOrEncCert.Bytes),
				)
			}
			result.Responses = append(result.Responses, EnrollmentResponseEntry{
				CertReqID:   response.CertReqID,
				Certificate: cert,
			})
			result.Certificates = append(result.Certificates, cert)
			if result.Certificate == nil {
				result.Certificate = cert
			}
		default:
			return nil, &ProtocolError{Operation: op, CertReqID: response.CertReqID, Status: response.Status}
		}
	}

	if result.Pending && len(result.PendingCertReqIDs) > 0 {
		result.PendingCertReqIDs = slices.Clip(result.PendingCertReqIDs)
	}

	return result, nil
}
