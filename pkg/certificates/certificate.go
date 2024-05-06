package certificates

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
)

type certificate struct {
	certificate   *x509.Certificate
	privateKey    *rsa.PrivateKey
	pem           *bytes.Buffer
	pemPrivateKey *bytes.Buffer
}

func (c *certificate) PEM() *bytes.Buffer {
	return c.pem
}

func (c *certificate) PEMPrivateKey() *bytes.Buffer {
	return c.pemPrivateKey
}

func (c *certificate) PrivateKey() *rsa.PrivateKey {
	return c.privateKey
}

func (c *certificate) Certificate() *x509.Certificate {
	return c.certificate
}
