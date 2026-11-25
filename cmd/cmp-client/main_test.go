package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	cmpclient "github.com/otpki/cmp-client"
	"github.com/otpki/iogo/crypto/x509"
	"github.com/otpki/otpki-pkg/cmp"
	"github.com/stretchr/testify/require"
)

func TestCLIInsecureStillRequiresCMPProtection(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	secretPath := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	require.NoError(t, os.WriteFile(secretPath, []byte("fixture-secret"), 0o600))
	for _, mode := range []string{"PBM", "PBMAC1", "unprotected"} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			req, _, _, err := cmp.DecodePKIMessage(raw)
			require.NoError(t, err)
			resp := &cmp.PKIMessage{Header: cmp.PKIHeader{Pvno: 2, Sender: req.Header.Recipient, Recipient: req.Header.Sender, TransactionID: req.Header.TransactionID, RecipNonce: req.Header.SenderNonce, SenderNonce: bytes.Repeat([]byte{4}, 16)}, Body: cmp.PKIBody{Type: cmp.BodyTypeIP, Value: cmp.CertRepMessage{Responses: []cmp.CertResponse{{CertReqID: 0, Status: cmp.PKIStatusInfo{Status: cmp.PKIStatusAccepted}, CertifiedKeyPair: cmp.CertifiedKeyPair{CertOrEncCert: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: certDER}}}}}}}
			switch mode {
			case "PBMAC1":
				alg, _, err := req.Header.ParsedProtectionAlg()
				require.NoError(t, err)
				require.Equal(t, "1.2.840.113549.1.5.14", alg.Algorithm.String())
				require.NoError(t, cmpclient.ApplyPBMAC1Protection(resp, []byte("fixture-secret"), nil))
			case "PBM":
				require.NoError(t, cmpclient.ApplyPBMProtection(resp, []byte("fixture-secret"), nil))
			}
			der, err := cmp.MarshalPKIMessage(resp)
			require.NoError(t, err)
			w.Header().Set("Content-Type", "application/pkixcmp")
			_, _ = w.Write(der)
		}))
		args := []string{"ir", "--url", server.URL, "--key", keyPath, "--secret-file", secretPath, "--common-name", "device"}
		if mode == "PBMAC1" {
			args = append(args, "--pbmac1")
		}
		var stdout, stderr bytes.Buffer
		require.Error(t, run(t.Context(), args, &stdout, &stderr))
		err = run(t.Context(), append(args, "--insecure"), &stdout, &stderr)
		if mode != "unprotected" {
			require.NoError(t, err)
			block, _ := pem.Decode(stdout.Bytes())
			require.NotNil(t, block)
			require.Equal(t, certDER, block.Bytes)
		} else {
			require.ErrorContains(t, err, "protection")
		}
		server.Close()
	}
}

func TestCLIHelpAndInvalidArguments(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"help"}, {"ir", "--help"}} {
		var out bytes.Buffer
		require.NoError(t, run(t.Context(), args, &out, &out))
		require.NotEmpty(t, out.String())
	}
	for _, args := range [][]string{{"unknown"}, {"ir"}, {"ir", "--url", "https://example.invalid", "--timeout", "0s"}, {"ir", "--url", "https://example.invalid", "--secret-file", "one", "--secret-env", "TWO"}} {
		var out bytes.Buffer
		require.Error(t, run(t.Context(), args, &out, &out))
	}
}
