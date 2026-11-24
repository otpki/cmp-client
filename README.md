# cmp-client

A Go CMP client library and command-line tool for enrollment and protocol testing.
Licensed under Apache-2.0. Requires Go 1.27.4 or newer.

The client uses the shared `cmp`, `crmf`, and `pkiutil` packages in
[`otpki-pkg`](https://github.com/otpki/otpki-pkg). It has no dependency on the
OTPKI server, generated server APIs, Docker, or private repository credentials.

## Capabilities

| Operation | Request protection | Behavior |
| --- | --- | --- |
| IR | PasswordBasedMac or PBMAC1 (PBKDF2/HMAC-SHA256) | CRMF signature POP; one or more requests |
| CR | Certificate signature | CRMF signature POP; one or more requests |
| KUR | Certificate signature | New-key CRMF signature POP; one or more requests |
| P10CR | Certificate signature | Validated PKCS#10 signature |
| Polling | Same protection as enrollment | Verified responses, transaction and nonce continuity, bounded retries/waits |
| Custom messages | Legacy PBM, PBMAC1, or signature | `Exchange` accepts the shared CMP wire model |
| Malformed/security tests | Caller-controlled DER | `SendRaw` performs only bounded HTTP transport |

High-level enrollment verifies response protection, version, transaction ID,
recipient nonce, sender/recipient names, request IDs, and issued public keys.
For signature responses, configure the exact server signing certificate with
`ServerCertificate`; certificates received in `extraCerts` or `caPubs` never
establish trust. Password-based enrollment authenticates MAC responses using the supplied
secret, or requires signature responses when a server certificate is pinned.
Legacy SHA-1 PBM is not enabled. Set `IRRequest.UsePBMAC1` or
`Protection.UsePBMAC1` for PBMAC1; legacy PBM remains the default.

Automatic certificate confirmation, a high-level revocation API, and
server-generated keys remain follow-up work. `Exchange` can carry caller-built
confirmation, revocation, and general messages. Enrollment returns the final
message/raw bytes and per-request results so callers can continue a transaction.
Persist issued private keys yourself; the CLI never generates or stores them.

## Go API

```go
client := cmpclient.New()
// For an explicitly configured local test system:
client = cmpclient.New(cmpclient.WithInsecureSkipTLSVerify())
// Equivalent when constructing/configuring a Client directly:
client.InsecureSkipTLSVerify = true
```

`InsecureSkipTLSVerify` disables HTTPS certificate verification only. CMP
protection and response correlation remain mandatory. By default TLS verifies
both the certificate chain and hostname. Plain HTTP endpoints are also supported;
use HTTPS when transport confidentiality is needed. A custom `HTTPClient` can
supply trusted CA certificates or mutual TLS; the insecure option supports
`*http.Transport` and leaves the supplied transport unchanged.

Typical initialization (imports abbreviated):

```go
key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil { return err }
recipient, err := cmpclient.DirectoryName(pkix.Name{CommonName: "Issuing CA"})
if err != nil { return err }
sender, err := cmpclient.DirectoryName(pkix.Name{})
if err != nil { return err }
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
defer cancel()
response, err := cmpclient.New().IR(ctx, cmpclient.IRRequest{
    URL: "https://pki.example/cmp/enroll",
    Sender: sender, Recipient: recipient,
    Subject: pkix.Name{CommonName: "device.example"},
    SignerKey: key, // The requested public key is derived from this signer.
    SharedSecret: secret, // Supplied by the caller's credential management.
    SenderKID: []byte("bootstrap-identity"),
})
if err != nil { return err }
_ = response.Certificate
```

For CR/KUR, supply `SignerCert`, `SignerKey`, and `POPSignerKey`, and set the
client's `ServerCertificate`. P10CR takes `CSRDER` and the message-protection
certificate/key. `Requests` accepts multiple CRMF entries with distinct,
non-negative `CertReqID` values. `Extensions` allows SANs and other requested
X.509 extensions. A supplied public key must match its POP signer.

`BuildIRMessage`, `BuildCRMessage`, `BuildKURMessage`, and `BuildP10CRMessage`
return unprotected messages for inspection/mutation. Apply the exported
protection helpers and send raw DER for negative tests. `VerifyResponse` can
verify a separately captured response against its original request. Authenticated
protocol rejection errors are available through `errors.As` as `*ProtocolError`.

## CLI

Build with `go build -o dist/cmp-client ./cmd/cmp-client` or run
`go run ./cmd/cmp-client --help`. After a version is published:

```sh
go install github.com/otpki/cmp-client/cmd/cmp-client@<version>
```

Initialize with a pre-existing PEM private key and a file containing the exact
secret bytes (a trailing newline is part of the secret):

```sh
cmp-client ir --url https://pki.example/cmp/enroll \
  --common-name device.example --recipient 'Issuing CA' \
  --key device-key.pem --sender-kid bootstrap-identity \
  --secret-file bootstrap-secret --out device-cert.pem
```

For a local server with an untrusted TLS certificate, append `--insecure`.
For PBMAC1 enrollment, append `--pbmac1`.
For an environment-provided secret, use `--secret-env CMP_SECRET` instead of
`--secret-file`. Secrets are never passed as literal CLI arguments or printed.

Signature-protected renewal:

```sh
cmp-client kur --url https://pki.example/cmp/enroll \
  --common-name device.example --key new-device-key.pem \
  --signer-cert device-cert.pem --signer-key device-key.pem \
  --server-cert cmp-signer.pem --out renewed-cert.pem
```

Use `cr` with the same arguments for certification, or `p10cr --csr request.pem`
with `--signer-cert`, `--signer-key`, and `--server-cert`. The CSR may be PEM or
DER. Private keys may be unencrypted PKCS#8, RSA PKCS#1, or EC SEC1 PEM.
`--timeout` covers the whole operation, including polling. `--ca-out` writes
returned CA publications separately. Certificate output defaults to stdout.
The CLI currently handles one certificate request per invocation; use the Go API
for multi-request enrollment or protocol mutation.

## Development and CI

Standard commands follow `otpki-pkg`: `just tools`, `just format`, `just lint`,
`just test`, and `just check`. `just check` includes formatting, lint, tests,
race tests, build, and `go mod tidy -diff`. It does not require a clean development
working tree; CI's shared workflow checks that commands leave tracked files clean.

Workflows reuse `otpki/.github` at `v1` for Go checks, workflow lint, dependency
review, CodeQL, and the fast-forward helper. Renovate and community health files
use organization defaults. Tagged releases run the same checks and package the
CLI for Linux, macOS, and Windows (amd64/arm64) with checksums and generated notes.
No container image is required for the client.

Tests use local HTTP/TLS fixtures and generated test credentials. They need no
running OTPKI server. Server interoperability is validated separately in core's
integration harness. Before publishing a version, verify anonymous dependency
resolution and hosted workflows, including fork PRs, and enable the organization
repository settings for reviews and private vulnerability reporting. Do not
publish local dependency replacements or credentials.
