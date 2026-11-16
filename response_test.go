package cmpclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	pkiutil "github.com/otpki/otpki-pkg/pkiutil"

	"github.com/otpki/otpki-pkg/crmf"

	cmp "github.com/otpki/otpki-pkg/cmp"
	"github.com/stretchr/testify/require"
)

func TestParseEnrollmentResultHandlesWaitingResponse(t *testing.T) {
	t.Parallel()

	rawResp := mustMarshalClientPKIMessage(t, &cmp.PKIMessage{
		Header: cmp.PKIHeader{Pvno: 2},
		Body: cmp.PKIBody{
			Type: cmp.BodyTypeCP,
			Value: cmp.CertRepMessage{
				Responses: []cmp.CertResponse{{
					CertReqID: 7,
					Status: cmp.PKIStatusInfo{
						Status: cmp.PKIStatusWaiting,
					},
				}},
			},
		},
	})

	result, err := parseEnrollmentResult(rawResp, cmp.BodyTypeCP, "CR")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Pending)
	require.Equal(t, 7, result.CertReqID)
	require.Equal(t, []int{7}, result.PendingCertReqIDs)
	require.Equal(t, 0, result.CheckAfter)
}

func TestParseEnrollmentResultHandlesPollRep(t *testing.T) {
	t.Parallel()

	rawResp := mustMarshalClientPKIMessage(t, &cmp.PKIMessage{
		Header: cmp.PKIHeader{Pvno: 2},
		Body: cmp.PKIBody{
			Type: cmp.BodyTypePollRep,
			Value: cmp.PollRepContent{
				{
					CertReqID:  9,
					CheckAfter: 5,
				},
			},
		},
	})

	result, err := parseEnrollmentResult(rawResp, cmp.BodyTypeCP, "CR")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Pending)
	require.Equal(t, 9, result.CertReqID)
	require.Equal(t, []int{9}, result.PendingCertReqIDs)
	require.Equal(t, 5, result.CheckAfter)
}

func TestParseEnrollmentResultHandlesMultiPollRep(t *testing.T) {
	t.Parallel()

	rawResp := mustMarshalClientPKIMessage(t, &cmp.PKIMessage{
		Header: cmp.PKIHeader{Pvno: 2},
		Body: cmp.PKIBody{
			Type: cmp.BodyTypePollRep,
			Value: cmp.PollRepContent{
				{
					CertReqID:  9,
					CheckAfter: 5,
				},
				{
					CertReqID:  12,
					CheckAfter: 3,
				},
			},
		},
	})

	result, err := parseEnrollmentResult(rawResp, cmp.BodyTypeCP, "CR")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Pending)
	require.Equal(t, 9, result.CertReqID)
	require.Equal(t, []int{9, 12}, result.PendingCertReqIDs)
	require.Equal(t, 5, result.CheckAfter)
}

func TestBuildIRMessageSupportsMultipleRequests(t *testing.T) {
	t.Parallel()

	keyOne, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyTwo, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	spkiOne, err := pkiutil.SubjectPublicKeyInfoFromPublicKey(keyOne.Public())
	require.NoError(t, err)
	spkiTwo, err := pkiutil.SubjectPublicKeyInfoFromPublicKey(keyTwo.Public())
	require.NoError(t, err)

	msg, err := BuildIRMessage(IRRequest{
		Sender:    asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true},
		Recipient: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true},
		Requests: []IRRequestEntry{
			{
				CertReqID: 11,
				Subject: pkix.Name{
					CommonName:   "cmp-ra-one",
					Organization: []string{"My Organization"},
					Country:      []string{"SE"},
				},
				PublicKey: spkiOne,
				SignerKey: keyOne,
			},
			{
				CertReqID: 12,
				Subject: pkix.Name{
					CommonName:   "cmp-ra-two",
					Organization: []string{"My Organization"},
					Country:      []string{"SE"},
				},
				PublicKey: spkiTwo,
				SignerKey: keyTwo,
			},
		},
	}, rand.Reader)
	require.NoError(t, err)

	crm, ok := msg.Body.Value.(crmf.CertReqMessages)
	require.True(t, ok)
	require.Len(t, crm, 2)
	require.Equal(t, 11, crm[0].CertReq.CertReqID)
	require.Equal(t, 12, crm[1].CertReq.CertReqID)
}

func mustMarshalClientPKIMessage(t *testing.T, msg *cmp.PKIMessage) []byte {
	t.Helper()

	der, err := cmp.MarshalPKIMessage(msg)
	require.NoError(t, err)
	return der
}
