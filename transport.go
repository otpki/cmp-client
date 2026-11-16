package cmpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
)

// SendRaw exchanges DER without CMP protection, correlation, or status checks.
// It exists for interoperability tools and malformed-message/security tests.
// Normal callers should use IR, CR, KUR, or P10CR.
func (c *Client) SendRaw(ctx context.Context, endpoint string, der []byte) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("nil client")
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = defaultHTTPClient()
	}
	limit := c.MaxResponseBytes
	if limit <= 0 {
		limit = 4 << 20
	}
	return postCMP(ctx, hc, endpoint, der, limit, c.InsecureSkipTLSVerify)
}

func postCMP(ctx context.Context, hc *http.Client, endpoint string, der []byte, limit int64, insecure bool) ([]byte, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("CMP endpoint must be an HTTP(S) URL without userinfo or fragment")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(der))
	if err != nil {
		return nil, fmt.Errorf("create CMP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/pkixcmp")
	req.Header.Set("Accept", "application/pkixcmp")
	// Reject redirects even when the caller supplies a custom HTTP client. A CMP
	// transaction must not forward a password-protected request to another endpoint.
	client := *hc
	if insecure {
		transport := hc.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		original, ok := transport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("InsecureSkipTLSVerify requires an *http.Transport")
		}
		clone := original.Clone()
		if clone.TLSClientConfig == nil {
			clone.TLSClientConfig = &tls.Config{}
		} else {
			clone.TLSClientConfig = clone.TLSClientConfig.Clone()
		}
		clone.TLSClientConfig.InsecureSkipVerify = true // #nosec G402 -- Explicit API/CLI opt-in for local test certificates; CMP authentication remains mandatory.
		client.Transport = clone
		defer clone.CloseIdleConnections()
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CMP HTTP exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CMP HTTP status %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/pkixcmp" {
		return nil, fmt.Errorf("unexpected CMP response media type %q", resp.Header.Get("Content-Type"))
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("CMP response exceeds %d bytes", limit)
	}
	// limit is caller-controlled; avoid integer overflow in limit+1.
	if limit >= 1<<62 {
		return nil, fmt.Errorf("invalid CMP response limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read CMP response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("CMP response exceeds %d bytes", limit)
	}
	return body, nil
}
