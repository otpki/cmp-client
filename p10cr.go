package cmpclient

import (
	"context"
	"crypto/rand"
	"fmt"

	cmp "github.com/otpki/otpki-pkg/cmp"
)

func (c *Client) P10CR(ctx context.Context, req P10CRRequest) (*P10CRResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("nil client")
	}
	if c.ServerCertificate == nil {
		return nil, fmt.Errorf("signature enrollment requires ServerCertificate")
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = defaultHTTPClient()
	}
	rnd := c.Rand
	if rnd == nil {
		rnd = rand.Reader
	}

	msg, err := BuildP10CRMessage(req, rnd)
	if err != nil {
		return nil, err
	}
	result, err := c.exchangeEnrollment(
		ctx,
		hc,
		req.URL,
		rnd,
		msg,
		cmp.BodyTypeCP,
		"P10CR",
		nil,
		func(msg *cmp.PKIMessage) error {
			return ApplySignatureProtection(msg, req.SignerCert, req.SignerKey)
		},
	)
	if err != nil {
		return nil, err
	}
	return &P10CRResponse{
		Certificate:  result.Certificate,
		Certificates: result.Certificates,
		Responses:    result.Responses,
		CAPubs:       result.CAPubs,
		RawResponse:  result.RawResponse,
		Message:      result.Message,
	}, nil
}
