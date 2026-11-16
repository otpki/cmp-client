module github.com/otpki/cmp-client

go 1.27.4

require (
	github.com/otpki/iogo v0.0.0-20261112152310-36bbc5e4b73f
	github.com/otpki/otpki-pkg v0.0.0-20261116151636-54f92c830ec9
	github.com/stretchr/testify v1.12.1
)

require (
	filippo.io/bigmod v0.1.0 // indirect
	github.com/cloudflare/circl v0.0.0-00010101000000-000000000000 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

replace github.com/cloudflare/circl => github.com/otpki/circl v0.0.0-20261112151406-a03bc4371af7

replace github.com/smallstep/pkcs7 => github.com/otpki/pkcs7 v0.0.0-20261112150827-3f426f339887
