package cmpclient

import (
	"context"
	"crypto/rand"
	"fmt"

	cmp "github.com/otpki/otpki-pkg/cmp"
)

// IR performs Initialization Request using PBM protection
func (c *Client) IR(ctx context.Context, req IRRequest) (*IRResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("nil client")
	}

	hc := c.HTTPClient
	if hc == nil {
		hc = defaultHTTPClient()
	}

	rnd := c.Rand
	if rnd == nil {
		rnd = rand.Reader
	}

	msg, err := BuildIRMessage(req, rnd)
	if err != nil {
		return nil, err
	}
	result, err := c.exchangeEnrollment(
		ctx,
		hc,
		req.URL,
		rnd,
		msg,
		cmp.BodyTypeIP,
		"IR",
		req.SharedSecret,
		func(msg *cmp.PKIMessage) error {
			return ApplyPBMProtection(msg, req.SharedSecret, rnd)
		},
	)
	if err != nil {
		return nil, err
	}
	return &IRResponse{
		Certificate:  result.Certificate,
		Certificates: result.Certificates,
		Responses:    result.Responses,
		CAPubs:       result.CAPubs,
		RawResponse:  result.RawResponse,
		Message:      result.Message,
	}, nil
}
