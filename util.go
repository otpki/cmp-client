package cmpclient

import (
	"fmt"
	"io"
)

func cloneBytes(b []byte) []byte { return append([]byte(nil), b...) }

func randomBytes(b []byte, random io.Reader) ([]byte, error) {
	if len(b) != 0 {
		return cloneBytes(b), nil
	}
	out := make([]byte, 16)
	if _, err := io.ReadFull(random, out); err != nil {
		return nil, fmt.Errorf("generate nonce/transaction ID: %w", err)
	}
	return out, nil
}
