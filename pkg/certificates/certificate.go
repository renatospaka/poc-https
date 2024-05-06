package certificates

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
)

type certificate struct {
	certificate    *x509.Certificate
	tlsCertificate tls.Certificate
	privateKey     *rsa.PrivateKey
	pem            *bytes.Buffer
	pemPrivateKey  *bytes.Buffer
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

func (c *certificate) TLSCertificate() tls.Certificate {
	return c.tlsCertificate
}
