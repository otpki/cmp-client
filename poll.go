package cmpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/otpki/iogo/crypto/x509"

	cmp "github.com/otpki/otpki-pkg/cmp"
)

type enrollmentResult struct {
	Message           *cmp.PKIMessage
	Certificate       *x509.Certificate
	Certificates      []*x509.Certificate
	Responses         []EnrollmentResponseEntry
	CAPubs            []*x509.Certificate
	RawResponse       []byte
	Pending           bool
	CertReqID         int
	PendingCertReqIDs []int
	CheckAfter        int
}

type protectMessageFunc func(msg *cmp.PKIMessage) error

func (c *Client) exchangeEnrollment(
	ctx context.Context,
	hc *http.Client,
	url string,
	rnd io.Reader,
	msg *cmp.PKIMessage,
	expectedBodyType cmp.PKIBodyType,
	op string,
	secret []byte,
	protect protectMessageFunc,
) (*enrollmentResult, error) {
	if msg == nil {
		return nil, fmt.Errorf("%s: nil request message", op)
	}
	if protect == nil {
		return nil, fmt.Errorf("%s: missing message protector", op)
	}

	rawResp, err := c.sendProtectedMessage(ctx, hc, url, msg, protect)
	if err != nil {
		return nil, err
	}

	if _, err := c.VerifyResponse(msg, rawResp, secret); err != nil {
		return nil, err
	}
	result, err := parseEnrollmentResult(rawResp, expectedBodyType, op)
	if err != nil {
		return nil, err
	}
	aggregate := mergeEnrollmentResult(nil, result)

	pendingIDs := expectedRequestIDs(msg)
	if msg.Body.Type == cmp.BodyTypeP10CR {
		id := -1
		if len(result.Responses) > 0 {
			id = result.Responses[0].CertReqID
		} else if len(result.PendingCertReqIDs) > 0 {
			id = result.PendingCertReqIDs[0]
		}
		if id != 0 && id != -1 {
			return nil, fmt.Errorf("unexpected PKCS#10 request ID %d", id)
		}
		pendingIDs = map[int]bool{id: true}
	}
	if err := checkResultIDs(result, pendingIDs); err != nil {
		return nil, err
	}
	for attempt := 0; result.Pending; attempt++ {
		limit := c.MaxPolls
		if limit <= 0 {
			limit = 100
		}
		if attempt >= limit {
			return nil, fmt.Errorf("CMP polling limit exceeded")
		}
		delay, err := c.pollDelay(result.CheckAfter)
		if err != nil {
			return nil, err
		}
		if err := waitForNextPoll(ctx, delay); err != nil {
			return nil, fmt.Errorf("%s pending poll wait: %w", op, err)
		}

		pollMsg, err := buildPollReqMessage(msg.Header, result.Message, result.PendingCertReqIDs, rnd)
		if err != nil {
			return nil, err
		}
		rawResp, err = c.sendProtectedMessage(ctx, hc, url, pollMsg, protect)
		if err != nil {
			return nil, err
		}

		if _, err := c.VerifyResponse(pollMsg, rawResp, secret); err != nil {
			return nil, err
		}
		result, err = parseEnrollmentResult(rawResp, expectedBodyType, op)
		if err != nil {
			return nil, err
		}
		active := make(map[int]bool)
		pollRequests, ok := pollMsg.Body.Value.(cmp.PollReqContent)
		if !ok {
			return nil, fmt.Errorf("invalid poll request body")
		}
		for _, request := range pollRequests {
			active[request.CertReqID] = true
		}
		if err := checkResultIDs(result, active); err != nil {
			return nil, err
		}
		aggregate = mergeEnrollmentResult(aggregate, result)
	}

	if len(aggregate.Responses) != len(pendingIDs) {
		return nil, fmt.Errorf("CMP response omitted certificate requests")
	}
	if err := checkIssuedKeys(msg, aggregate); err != nil {
		return nil, err
	}
	return aggregate, nil
}

func (c *Client) sendProtectedMessage(
	ctx context.Context,
	hc *http.Client,
	url string,
	msg *cmp.PKIMessage,
	protect protectMessageFunc,
) ([]byte, error) {
	if err := protect(msg); err != nil {
		return nil, err
	}

	reqDER, err := cmp.MarshalPKIMessage(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIMessage: %w", err)
	}

	limit := c.MaxResponseBytes
	if limit <= 0 {
		limit = 4 << 20
	}
	return postCMP(ctx, hc, url, reqDER, limit, c.InsecureSkipTLSVerify)
}

func buildPollReqMessage(
	base cmp.PKIHeader,
	prevResp *cmp.PKIMessage,
	certReqIDs []int,
	rnd io.Reader,
) (*cmp.PKIMessage, error) {
	nonce, err := randomBytes(nil, rnd)
	if err != nil {
		return nil, err
	}
	content := make(cmp.PollReqContent, 0, len(certReqIDs))
	for _, certReqID := range certReqIDs {
		content = append(content, cmp.PollReq{CertReqID: certReqID})
	}

	msg := &cmp.PKIMessage{
		Header: cmp.PKIHeader{
			Pvno:          base.Pvno,
			Sender:        base.Sender,
			Recipient:     base.Recipient,
			SenderKID:     cloneBytes(base.SenderKID),
			RecipKID:      cloneBytes(base.RecipKID),
			TransactionID: cloneBytes(base.TransactionID),
			SenderNonce:   nonce,
		},
		Body: cmp.PKIBody{
			Type:  cmp.BodyTypePollReq,
			Value: content,
		},
	}

	if prevResp != nil {
		msg.Header.RecipNonce = cloneBytes(prevResp.Header.SenderNonce)
	}

	return msg, nil
}

func waitForNextPoll(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) pollDelay(seconds int) (time.Duration, error) {
	maxWait := c.MaxPollWait
	if maxWait <= 0 {
		maxWait = 5 * time.Minute
	}
	if seconds < 0 || int64(seconds) > int64(maxWait/time.Second) {
		return 0, fmt.Errorf("CMP checkAfter outside permitted range")
	}
	delay := time.Duration(seconds) * time.Second
	minimum := c.PollInterval
	if minimum <= 0 {
		minimum = time.Second
	}
	if delay < minimum {
		delay = minimum
	}
	if delay > maxWait {
		return 0, fmt.Errorf("CMP poll delay exceeds maximum")
	}
	return delay, nil
}

func mergeEnrollmentResult(dst, src *enrollmentResult) *enrollmentResult {
	if src == nil {
		return dst
	}
	if dst == nil {
		dst = &enrollmentResult{}
	}

	dst.Message = src.Message
	dst.RawResponse = src.RawResponse
	dst.Pending = src.Pending
	dst.CertReqID = src.CertReqID
	dst.PendingCertReqIDs = append([]int(nil), src.PendingCertReqIDs...)
	dst.CheckAfter = src.CheckAfter

	if len(dst.CAPubs) == 0 && len(src.CAPubs) > 0 {
		dst.CAPubs = append([]*x509.Certificate(nil), src.CAPubs...)
	}

	seen := make(map[int]struct{}, len(dst.Responses))
	for _, response := range dst.Responses {
		seen[response.CertReqID] = struct{}{}
	}

	for _, response := range src.Responses {
		if _, ok := seen[response.CertReqID]; ok {
			continue
		}
		seen[response.CertReqID] = struct{}{}
		dst.Responses = append(dst.Responses, response)
		if response.Certificate != nil {
			dst.Certificates = append(dst.Certificates, response.Certificate)
			if dst.Certificate == nil {
				dst.Certificate = response.Certificate
			}
		}
	}

	return dst
}
