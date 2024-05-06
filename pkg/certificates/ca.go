package certificates

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

func (s *SelfSigned) SetupCA() error {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Country:            []string{"BR"},
			Organization:       []string{"Goiaba LTDA"},
			OrganizationalUnit: []string{},
			Locality:           []string{"São Paulo"},
			Province:           []string{"SP"},
			StreetAddress:      []string{"Av Rio Branco, 1509"},
			PostalCode:         []string{"00000-000"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// criando as chaves privada e pública
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return errors.Join(ErrCertificadoCAChavePrivada, err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return errors.Join(ErrCertificadoCA, err)
	}

	// gera o PEM e a Chave PEM
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivateKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	})

	c := &certificate{
		certificate:   ca,
		privateKey:    caPrivateKey,
		pem:           caPEM,
		pemPrivateKey: caPrivateKeyPEM,
	}
	s.ca = c
	return nil
}
