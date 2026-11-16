package cmpclient

import (
	"io"
	"net/http"
	"time"

	"github.com/otpki/iogo/crypto/x509"
)

// Client performs CMP enrollment. Configure fields before use; do not change them
// concurrently with requests. The zero value uses secure HTTP defaults.
type Client struct {
	HTTPClient *http.Client
	// InsecureSkipTLSVerify disables HTTPS certificate verification when explicitly
	// enabled for local development. CMP message verification is still required.
	InsecureSkipTLSVerify bool
	// Rand defaults to crypto/rand.Reader. A custom source must be concurrency safe.
	Rand io.Reader
	// ServerCertificate pins the exact CMP response signer. extraCerts and caPubs
	// are never used as trust anchors. Signature-protected requests require a pin.
	// PBM enrollment can instead authenticate responses with its shared secret.
	ServerCertificate *x509.Certificate
	// PollInterval is the minimum delay between polls; server checkAfter is honored.
	PollInterval time.Duration
	// MaxPolls defaults to 100, MaxPollWait to five minutes.
	MaxPolls    int
	MaxPollWait time.Duration
	// MaxResponseBytes defaults to 4 MiB, for raw and verified exchanges alike.
	MaxResponseBytes int64
}

// Option configures a new client.
type Option func(*Client)

// WithInsecureSkipTLSVerify opts out of HTTPS certificate verification.
func WithInsecureSkipTLSVerify() Option {
	return func(c *Client) { c.InsecureSkipTLSVerify = true }
}

// New returns a client with TLS verification and a 30-second HTTP timeout.
func New(options ...Option) *Client {
	c := &Client{HTTPClient: defaultHTTPClient()}
	for _, option := range options {
		if option != nil {
			option(c)
		}
	}
	return c
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}
