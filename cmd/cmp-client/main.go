// Command cmp-client performs CMP enrollment with PBM, PBMAC1 or signature protection.
package main

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	cmpclient "github.com/otpki/cmp-client"
	"github.com/otpki/iogo/crypto/x509"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := fmt.Fprintln(stdout, "Usage: cmp-client <ir|cr|kur|p10cr> [options]\nRun cmp-client <command> --help for options.")
		return err
	}
	command := strings.ToLower(args[0])
	if command != "ir" && command != "cr" && command != "kur" && command != "p10cr" {
		return fmt.Errorf("unknown command %q", args[0])
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	endpoint := flags.String("url", "", "CMP HTTP(S) endpoint")
	commonName := flags.String("common-name", "", "requested subject common name (CRMF operations)")
	recipientName := flags.String("recipient", "", "recipient common name; defaults to pinned server certificate subject")
	keyPath := flags.String("key", "", "requested certificate's PEM private key (IR/CR/KUR)")
	signerKeyPath := flags.String("signer-key", "", "PEM message-protection private key (CR/KUR/P10CR)")
	signerCertPath := flags.String("signer-cert", "", "PEM message-protection certificate (CR/KUR/P10CR)")
	serverCertPath := flags.String("server-cert", "", "PEM certificate pin for CMP response signatures")
	csrPath := flags.String("csr", "", "PEM or DER PKCS#10 request (P10CR)")
	usePBMAC1 := flags.Bool("pbmac1", false, "use PBMAC1 (PBKDF2/HMAC-SHA-256) for IR")
	secretFile := flags.String("secret-file", "", "file containing exact shared secret bytes (IR)")
	secretEnv := flags.String("secret-env", "", "environment variable containing the shared secret (IR)")
	senderKID := flags.String("sender-kid", "", "bootstrap identity / senderKID")
	output := flags.String("out", "", "write issued certificate PEM here; default stdout")
	caOutput := flags.String("ca-out", "", "optional output for returned caPubs (not trust anchors)")
	insecure := flags.Bool("insecure", false, "skip HTTPS certificate verification; CMP protection verification remains enabled")
	timeout := flags.Duration("timeout", 5*time.Minute, "overall enrollment deadline, including polling")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *endpoint == "" {
		return fmt.Errorf("--url is required")
	}
	if *timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	if *usePBMAC1 && command != "ir" {
		return fmt.Errorf("--pbmac1 is supported with IR; use Exchange for other MAC-protected messages")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	client := cmpclient.New()
	client.InsecureSkipTLSVerify = *insecure
	var err error
	var serverCert *x509.Certificate
	if *serverCertPath != "" {
		serverCert, err = readCertificate(*serverCertPath)
		if err != nil {
			return err
		}
		client.ServerCertificate = serverCert
	}
	recipient, err := cmpclient.DirectoryName(pkix.Name{CommonName: *recipientName})
	if err != nil {
		return err
	}
	if *recipientName == "" && serverCert != nil {
		recipient = asn1.RawValue{Class: 2, Tag: 4, IsCompound: true, Bytes: serverCert.RawSubject}
	}
	sender, err := cmpclient.DirectoryName(pkix.Name{})
	if err != nil {
		return err
	}
	var issued *x509.Certificate
	var caPubs []*x509.Certificate
	if command == "ir" {
		if (*secretFile == "") == (*secretEnv == "") {
			return fmt.Errorf("IR requires exactly one of --secret-file and --secret-env")
		}
		var secret []byte
		if *secretFile != "" {
			secret, err = os.ReadFile(*secretFile) // #nosec G703 -- The local CLI user explicitly selects the credential file.
		} else {
			secret = []byte(os.Getenv(*secretEnv))
		}
		if err != nil {
			return fmt.Errorf("read bootstrap secret: %w", err)
		}
		if len(secret) == 0 {
			return fmt.Errorf("empty bootstrap secret")
		}
		key, err := readKey(*keyPath)
		if err != nil {
			return err
		}
		response, err := client.IR(ctx, cmpclient.IRRequest{UsePBMAC1: *usePBMAC1, URL: *endpoint, Sender: sender, Recipient: recipient, Subject: pkix.Name{CommonName: *commonName}, SignerKey: key, SharedSecret: secret, SenderKID: []byte(*senderKID)})
		if err != nil {
			return err
		}
		issued = response.Certificate
		caPubs = response.CAPubs
	} else {
		if serverCert == nil {
			return fmt.Errorf("--server-cert is required for signature-protected enrollment")
		}
		cert, err := readCertificate(*signerCertPath)
		if err != nil {
			return err
		}
		signer, err := readKey(*signerKeyPath)
		if err != nil {
			return err
		}
		sender = asn1.RawValue{Class: 2, Tag: 4, IsCompound: true, Bytes: cert.RawSubject}
		if command == "p10cr" {
			csr, err := os.ReadFile(*csrPath) // #nosec G703 -- The local CLI user explicitly selects the CSR file.
			if err != nil {
				return fmt.Errorf("read CSR: %w", err)
			}
			if block, _ := pem.Decode(csr); block != nil {
				csr = block.Bytes
			}
			response, err := client.P10CR(ctx, cmpclient.P10CRRequest{URL: *endpoint, Sender: sender, Recipient: recipient, SignerCert: cert, SignerKey: signer, CSRDER: csr, SenderKID: []byte(*senderKID)})
			if err != nil {
				return err
			}
			issued = response.Certificate
			caPubs = response.CAPubs
		} else {
			key, err := readKey(*keyPath)
			if err != nil {
				return err
			}
			request := cmpclient.CRRequest{URL: *endpoint, Sender: sender, Recipient: recipient, Subject: pkix.Name{CommonName: *commonName}, SignerCert: cert, SignerKey: signer, POPSignerKey: key, SenderKID: []byte(*senderKID)}
			var response *cmpclient.CRResponse
			if command == "cr" {
				response, err = client.CR(ctx, request)
			} else {
				response, err = client.KUR(ctx, request)
			}
			if err != nil {
				return err
			}
			issued = response.Certificate
			caPubs = response.CAPubs
		}
	}
	if issued == nil {
		return fmt.Errorf("CMP enrollment returned no certificate")
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued.Raw})
	if *output != "" {
		if err := os.WriteFile(*output, encoded, 0o600); err != nil { // #nosec G703 -- The local CLI user explicitly selects the output file.
			return err
		}
	} else {
		if _, err := stdout.Write(encoded); err != nil {
			return err
		}
	}
	if *caOutput != "" {
		var chain []byte
		for _, cert := range caPubs {
			chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
		}
		if err := os.WriteFile(*caOutput, chain, 0o600); err != nil { // #nosec G703 -- The local CLI user explicitly selects the CA output file.
			return err
		}
	}
	return nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path) // #nosec G304,G703 -- The local CLI user explicitly selects the input file.
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

func readKey(path string) (crypto.Signer, error) {
	if path == "" {
		return nil, fmt.Errorf("private key path is required")
	}
	raw, err := os.ReadFile(path) // #nosec G304,G703 -- The local CLI user explicitly selects the input file.
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("private key must be PEM encoded")
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}
	return signer, nil
}
