// Package cmpclient implements CMP enrollment over HTTP(S): initialization (IR)
// with PasswordBasedMac or PBMAC1, certification (CR), key update (KUR), and PKCS#10
// certification (P10CR) with certificate-signature protection. It supports multiple
// CRMF requests and authenticated polling with nonce continuity.
//
// TLS certificates are verified by default. WithInsecureSkipTLSVerify is an
// explicit opt-out for local test systems. It does not disable CMP authentication:
// responses require a password-based MAC or an explicitly pinned signer certificate.
// Wire models, cryptographic primitives, and CRMF POP come from otpki-pkg.
//
// Use Exchange for caller-built protected requests and SendRaw for malformed
// protocol/security tests. The package never imports the OTPKI server.
// Automatic certificate confirmation, server-generated keys, and a high-level
// revocation API are separate follow-up capabilities.
package cmpclient
