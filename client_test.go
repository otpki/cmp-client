package cmpclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otpki/iogo/crypto/x509"
	"github.com/otpki/otpki-pkg/cmp"
	"github.com/otpki/otpki-pkg/crmf"
	"github.com/otpki/otpki-pkg/oids"
	"github.com/otpki/otpki-pkg/pkiutil"
	"github.com/stretchr/testify/require"
)

var testSecret = []byte("test-only-bootstrap-secret")

func testIdentity(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CMP test signer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func responseFor(t *testing.T, request *cmp.PKIMessage, body cmp.PKIBody) *cmp.PKIMessage {
	t.Helper()
	return &cmp.PKIMessage{Header: cmp.PKIHeader{Pvno: request.Header.Pvno, Sender: request.Header.Recipient, Recipient: request.Header.Sender, TransactionID: cloneBytes(request.Header.TransactionID), RecipNonce: cloneBytes(request.Header.SenderNonce), SenderNonce: bytes.Repeat([]byte{7}, 16)}, Body: body}
}

func requestForTest(t *testing.T) *cmp.PKIMessage {
	t.Helper()
	name, err := DirectoryName(pkix.Name{CommonName: "test"})
	require.NoError(t, err)
	return &cmp.PKIMessage{Header: cmp.PKIHeader{Pvno: 2, Sender: name, Recipient: name, TransactionID: bytes.Repeat([]byte{1}, 16), SenderNonce: bytes.Repeat([]byte{2}, 16)}, Body: cmp.PKIBody{Type: cmp.BodyTypeGenM, Value: cmp.GenMsgContent{{InfoType: oids.OidCMPCACerts}}}}
}

func TestVerifyResponseRejectsTamperingAndCorrelationErrors(t *testing.T) {
	t.Parallel()
	mutations := map[string]func(*cmp.PKIMessage){
		"transaction":        func(m *cmp.PKIMessage) { m.Header.TransactionID = []byte("wrong") },
		"recipient nonce":    func(m *cmp.PKIMessage) { m.Header.RecipNonce = []byte("wrong") },
		"short sender nonce": func(m *cmp.PKIMessage) { m.Header.SenderNonce = []byte("short") },
		"version":            func(m *cmp.PKIMessage) { m.Header.Pvno = 3 },
		"recipient":          func(m *cmp.PKIMessage) { m.Header.Recipient, _ = DirectoryName(pkix.Name{CommonName: "wrong"}) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := requestForTest(t)
			response := responseFor(t, request, cmp.PKIBody{Type: cmp.BodyTypeGenP, Value: cmp.GenMsgContent{}})
			mutate(response)
			require.NoError(t, ApplyPBMProtection(response, testSecret, rand.Reader))
			raw := mustMarshalClientPKIMessage(t, response)
			_, err := New().VerifyResponse(request, raw, testSecret)
			require.Error(t, err)
		})
	}
	request := requestForTest(t)
	response := responseFor(t, request, cmp.PKIBody{Type: cmp.BodyTypeGenP, Value: cmp.GenMsgContent{}})
	raw := mustMarshalClientPKIMessage(t, response)
	_, err := New().VerifyResponse(request, raw, testSecret)
	require.ErrorContains(t, err, "protection")
	require.NoError(t, ApplyPBMProtection(response, testSecret, rand.Reader))
	raw = mustMarshalClientPKIMessage(t, response)
	_, err = New().VerifyResponse(request, raw, testSecret)
	require.NoError(t, err)
	_, err = New().VerifyResponse(request, raw, []byte("wrong-secret"))
	require.ErrorContains(t, err, "mismatch")
	response.Protection.Bytes[0] ^= 1
	_, err = New().VerifyResponse(request, mustMarshalClientPKIMessage(t, response), testSecret)
	require.ErrorContains(t, err, "mismatch")
}

func TestSignatureResponseUsesOnlyPinnedSigner(t *testing.T) {
	t.Parallel()
	cert, key := testIdentity(t)
	other, otherKey := testIdentity(t)
	request := requestForTest(t)
	response := responseFor(t, request, cmp.PKIBody{Type: cmp.BodyTypeGenP, Value: cmp.GenMsgContent{}})
	require.NoError(t, ApplySignatureProtection(response, cert, key))
	client := New()
	client.ServerCertificate = cert
	_, err := client.VerifyResponse(request, mustMarshalClientPKIMessage(t, response), nil)
	require.NoError(t, err)
	// Supplying a new valid signer via extraCerts cannot replace the configured pin.
	require.NoError(t, ApplySignatureProtection(response, other, otherKey))
	_, err = client.VerifyResponse(request, mustMarshalClientPKIMessage(t, response), nil)
	require.Error(t, err)
	require.NoError(t, ApplyPBMProtection(response, testSecret, nil))
	_, err = client.VerifyResponse(request, mustMarshalClientPKIMessage(t, response), testSecret)
	require.Error(t, err)
}

func TestResponseRejectsExcessivePBMWork(t *testing.T) {
	t.Parallel()
	request := requestForTest(t)
	response := responseFor(t, request, cmp.PKIBody{Type: cmp.BodyTypeGenP, Value: cmp.GenMsgContent{}})
	require.NoError(t, ApplyPBMProtection(response, testSecret, nil))
	params, err := asn1.Marshal(cmp.PBMParameter{Salt: bytes.Repeat([]byte{1}, 16), IterationCount: cmp.MaxPBMIterations + 1, OWF: algSHA256(), MAC: algHMACSHA256()})
	require.NoError(t, err)
	require.NoError(t, response.Header.SetProtectionAlg(pkiutil.AlgorithmIdentifier{Algorithm: oids.OidPasswordBasedMAC, Parameters: asn1.RawValue{FullBytes: params}}))
	_, err = New().VerifyResponse(request, mustMarshalClientPKIMessage(t, response), testSecret)
	require.ErrorContains(t, err, "iterationCount")
}

func TestTransportBoundsAndTLS(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
		media  string
		body   string
	}{
		{"status", 500, "application/pkixcmp", "private server details"},
		{"media", 200, "text/html", "<html>"},
		{"size", 200, "application/pkixcmp", "123456789"},
		{"redirect", 307, "application/pkixcmp", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.media)
				w.Header().Set("Location", "https://example.invalid")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := New()
			client.MaxResponseBytes = 8
			_, err := client.SendRaw(t.Context(), server.URL, []byte{1})
			require.Error(t, err)
			require.NotContains(t, err.Error(), "private server details")
		})
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Content-Type", "application/pkixcmp") }))
	defer tlsServer.Close()
	_, err := New().SendRaw(t.Context(), tlsServer.URL, nil)
	require.Error(t, err)
	insecure := New(WithInsecureSkipTLSVerify())
	_, err = insecure.SendRaw(t.Context(), tlsServer.URL, nil)
	require.NoError(t, err)
	insecure = &Client{InsecureSkipTLSVerify: true}
	_, err = insecure.SendRaw(t.Context(), tlsServer.URL, nil)
	require.NoError(t, err)
}

type failingRandom struct{}

func (failingRandom) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestBuildersPropagateRandomFailuresAndValidateKeys(t *testing.T) {
	t.Parallel()
	_, key := testIdentity(t)
	_, err := BuildIRMessage(IRRequest{SignerKey: key}, failingRandom{})
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	_, err = buildPollReqMessage(cmp.PKIHeader{}, nil, []int{0}, failingRandom{})
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	_, other := testIdentity(t)
	spki, err := pkiutil.SubjectPublicKeyInfoFromPublicKey(other.Public())
	require.NoError(t, err)
	_, err = BuildIRMessage(IRRequest{SignerKey: key, PublicKey: spki}, nil)
	require.ErrorContains(t, err, "does not match")
	_, err = BuildIRMessage(IRRequest{Requests: []IRRequestEntry{{SignerKey: key, CertReqID: 1}, {SignerKey: key, CertReqID: 1}}}, nil)
	require.ErrorContains(t, err, "duplicate")
}

func TestEnrollmentOperations(t *testing.T) {
	t.Parallel()
	for _, op := range []string{"IR", "CR", "KUR", "P10CR"} {
		t.Run(op, func(t *testing.T) {
			t.Parallel()
			cert, signer := testIdentity(t)
			_, key := testIdentity(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				msg, _, _, err := cmp.DecodePKIMessage(body)
				require.NoError(t, err)
				protected, err := cmp.ProtectedPartFromWire(msg)
				require.NoError(t, err)
				if op == "IR" {
					alg, present, err := msg.Header.ParsedProtectionAlg()
					require.NoError(t, err)
					require.True(t, present)
					var parameters cmp.PBMParameter
					_, err = asn1.Unmarshal(alg.Parameters.FullBytes, &parameters)
					require.NoError(t, err)
					mac, err := cmp.ComputePBM(testSecret, protected, parameters, false)
					require.NoError(t, err)
					require.True(t, hmac.Equal(mac, msg.Protection.Bytes))
				} else {
					require.NoError(t, pkiutil.VerifySignature(cert.PublicKey, x509.ECDSAWithSHA256, protected, msg.Protection.Bytes))
				}
				var pub crypto.PublicKey
				id := 0
				replyType := cmp.BodyTypeCP
				if msg.Body.Type == cmp.BodyTypeP10CR {
					csrDER, ok := msg.Body.Value.([]byte)
					require.True(t, ok)
					csr, err := x509.ParseCertificateRequest(csrDER)
					require.NoError(t, err)
					pub = csr.PublicKey
					id = -1
				} else {
					requests, ok := msg.Body.Value.(crmf.CertReqMessages)
					require.True(t, ok)
					pub, err = crmf.PublicKey(requests[0].CertReq)
					require.NoError(t, err)
					if msg.Body.Type == cmp.BodyTypeIR {
						replyType = cmp.BodyTypeIP
					}
					if msg.Body.Type == cmp.BodyTypeKUR {
						replyType = cmp.BodyTypeKUP
					}
				}
				issued, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "issued"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}, cert, pub, signer)
				require.NoError(t, err)
				response := responseFor(t, msg, cmp.PKIBody{Type: replyType, Value: cmp.CertRepMessage{Responses: []cmp.CertResponse{{CertReqID: id, Status: cmp.PKIStatusInfo{Status: cmp.PKIStatusAccepted}, CertifiedKeyPair: cmp.CertifiedKeyPair{CertOrEncCert: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: issued}}}}}})
				if op == "IR" {
					require.NoError(t, ApplyPBMProtection(response, testSecret, nil))
				} else {
					require.NoError(t, ApplySignatureProtection(response, cert, signer))
				}
				w.Header().Set("Content-Type", "application/pkixcmp")
				_, _ = w.Write(mustMarshalClientPKIMessage(t, response))
			}))
			defer server.Close()
			client := New()
			name, err := DirectoryName(pkix.Name{CommonName: "endpoint"})
			require.NoError(t, err)
			switch op {
			case "IR":
				resp, err := client.IR(t.Context(), IRRequest{URL: server.URL, Sender: name, Recipient: name, SharedSecret: testSecret, SignerKey: key})
				require.NoError(t, err)
				require.NotNil(t, resp.Certificate)
			case "CR", "KUR":
				client.ServerCertificate = cert
				req := CRRequest{URL: server.URL, Sender: name, Recipient: name, SignerCert: cert, SignerKey: signer, POPSignerKey: key}
				var resp *CRResponse
				if op == "CR" {
					resp, err = client.CR(t.Context(), req)
				} else {
					resp, err = client.KUR(t.Context(), req)
				}
				require.NoError(t, err)
				require.NotNil(t, resp.Certificate)
			case "P10CR":
				client.ServerCertificate = cert
				csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "issued"}}, key)
				require.NoError(t, err)
				resp, err := client.P10CR(t.Context(), P10CRRequest{URL: server.URL, Sender: name, Recipient: name, SignerCert: cert, SignerKey: signer, CSRDER: csr})
				require.NoError(t, err)
				require.NotNil(t, resp.Certificate)
			}
		})
	}
}

func TestPollingCancellationAndNonceContinuity(t *testing.T) {
	t.Parallel()
	_, key := testIdentity(t)
	var requests atomic.Int32
	var previousNonce []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		msg, _, _, err := cmp.DecodePKIMessage(raw)
		require.NoError(t, err)
		if requests.Add(1) > 1 {
			require.Equal(t, previousNonce, msg.Header.RecipNonce)
			require.Equal(t, cmp.BodyTypePollReq, msg.Body.Type)
		}
		response := responseFor(t, msg, cmp.PKIBody{Type: cmp.BodyTypePollRep, Value: cmp.PollRepContent{{CertReqID: 0, CheckAfter: 0}}})
		previousNonce = cloneBytes(response.Header.SenderNonce)
		require.NoError(t, ApplyPBMProtection(response, testSecret, nil))
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(mustMarshalClientPKIMessage(t, response))
	}))
	defer server.Close()
	client := New()
	client.PollInterval = time.Millisecond
	client.MaxPolls = 2
	_, err := client.IR(t.Context(), IRRequest{URL: server.URL, SignerKey: key, SharedSecret: testSecret})
	require.ErrorContains(t, err, "polling limit")
	require.EqualValues(t, 3, requests.Load())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err = waitForNextPoll(ctx, time.Hour)
	require.ErrorIs(t, err, context.Canceled)
}

func TestProtocolErrorRetainsStatus(t *testing.T) {
	t.Parallel()
	raw := mustMarshalClientPKIMessage(t, &cmp.PKIMessage{Header: cmp.PKIHeader{Pvno: 2}, Body: cmp.PKIBody{Type: cmp.BodyTypeError, Value: cmp.ErrorMsgContent{Status: cmp.PKIStatusInfo{Status: cmp.PKIStatusRejection}, ErrorCode: 42}}})
	_, err := parseEnrollmentResult(raw, cmp.BodyTypeIP, "IR")
	var protocolErr *ProtocolError
	require.True(t, errors.As(err, &protocolErr))
	require.Equal(t, 42, protocolErr.Code)
}
