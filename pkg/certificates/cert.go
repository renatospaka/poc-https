package certificates

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"
)

func (s *SelfSigned) SetupCert() error {
	if s.ca.certificate == nil {
		return ErrCertificadoCAInvalido
	}
	caCert := s.ca.certificate
	caPrivateKey := s.ca.privateKey

	// configuração do certificado do Servidor
	cert := &x509.Certificate{
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
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		s.cert = nil
		return errors.Join(ErrCertificadoCertChavePrivada, err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		s.cert = nil
		return errors.Join(ErrCertificadoCert, err)
	}

	// PEM encode
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivateKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivateKey),
	})

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivateKeyPEM.Bytes())
	if err != nil {
		s.cert = nil
		return errors.Join(ErrCertificadoNotPaired, err)
	}

	err = s.SetupServerTLSConfig(serverCert)
	if err != nil {
		s.cert = nil
		return err
	}

	err = s.SetupClientTLSConfig()
	if err != nil {
		s.cert = nil
		return err
	}

	c := &certificate{
		certificate:   cert,
		privateKey:    certPrivateKey,
		pem:           certPEM,
		pemPrivateKey: certPrivateKeyPEM,
	}
	s.cert = c
	return nil
}
