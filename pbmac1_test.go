package cmpclient

import (
	"bytes"
	"crypto/hmac"
	"encoding/asn1"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/otpki/otpki-pkg/cmp"
	"github.com/otpki/otpki-pkg/oids"
	"github.com/stretchr/testify/require"
)

func TestPBMAC1ResponseVerification(t *testing.T) {
	t.Parallel()
	request := requestForTest(t)
	require.NoError(t, ApplyPBMAC1Protection(request, testSecret, nil))
	response := responseFor(t, request, cmp.PKIBody{Type: cmp.BodyTypePKIConf})
	require.NoError(t, ApplyPBMAC1Protection(response, testSecret, nil))
	requestAlg, _, _ := request.Header.ParsedProtectionAlg()
	responseAlg, _, _ := response.Header.ParsedProtectionAlg()
	require.NotEqual(t, requestAlg.Parameters.FullBytes, responseAlg.Parameters.FullBytes)
	wire := mustMarshalClientPKIMessage(t, response)
	_, err := New().VerifyResponse(request, wire, testSecret)
	require.NoError(t, err)
	_, err = New().VerifyResponse(request, wire, []byte("incorrect"))
	require.ErrorContains(t, err, "MAC mismatch")
	response.Protection.Bytes[0] ^= 1
	_, err = New().VerifyResponse(request, mustMarshalClientPKIMessage(t, response), testSecret)
	require.ErrorContains(t, err, "MAC mismatch")
	require.NoError(t, ApplyPBMProtection(response, testSecret, nil))
	_, err = New().VerifyResponse(request, mustMarshalClientPKIMessage(t, response), testSecret)
	require.ErrorContains(t, err, "downgrade")
	cert, signer := testIdentity(t)
	require.NoError(t, ApplySignatureProtection(response, cert, signer))
	pinned := New()
	pinned.ServerCertificate = cert
	_, err = pinned.VerifyResponse(request, mustMarshalClientPKIMessage(t, response), testSecret)
	require.NoError(t, err)
}

func TestPBMAC1Exchange(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		request, _, _, err := cmp.DecodePKIMessage(wire)
		require.NoError(t, err)
		alg, ok, err := request.Header.ParsedProtectionAlg()
		require.NoError(t, err)
		require.True(t, ok)
		require.True(t, alg.Algorithm.Equal(oids.OidPBMAC1))
		var parameters cmp.PBMAC1Params
		_, err = asn1.Unmarshal(alg.Parameters.FullBytes, &parameters)
		require.NoError(t, err)
		protected, err := cmp.ProtectedPartFromWire(request)
		require.NoError(t, err)
		mac, err := cmp.ComputePBMAC1(testSecret, protected, parameters, false)
		require.NoError(t, err)
		require.True(t, hmac.Equal(mac, request.Protection.Bytes))
		response := responseFor(t, request, cmp.PKIBody{Type: cmp.BodyTypePKIConf})
		require.NoError(t, ApplyPBMAC1Protection(response, testSecret, nil))
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(mustMarshalClientPKIMessage(t, response))
	}))
	defer server.Close()
	response, err := New().Exchange(t.Context(), server.URL, requestForTest(t), Protection{SharedSecret: testSecret, UsePBMAC1: true})
	require.NoError(t, err)
	require.Equal(t, cmp.BodyTypePKIConf, response.Body.Type)
}

func TestPBMAC1ProtectionRejectsMissingInputs(t *testing.T) {
	t.Parallel()
	require.Error(t, ApplyPBMAC1Protection(nil, testSecret, nil))
	require.Error(t, ApplyPBMAC1Protection(requestForTest(t), nil, nil))
	require.Error(t, ApplyPBMAC1Protection(requestForTest(t), testSecret, bytes.NewReader(nil)))
}
