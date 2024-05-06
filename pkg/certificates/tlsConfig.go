package certificates

import (
	"crypto/tls"
	"crypto/x509"
)

func (s *SelfSigned) SetupServerTLSConfig(server tls.Certificate) error {
	if server.Certificate == nil {
		return ErrCertificadoCertInvalido
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{server},
	}
	s.server = config
	return nil
}

func (s *SelfSigned) SetupClientTLSConfig() error {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(s.ca.pem.Bytes())

	config := &tls.Config{
		RootCAs: pool,
	}
	s.client = config
	return nil
}

func (s *SelfSigned) ClientTLS() *tls.Config {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(s.ca.pem.Bytes())

	config := &tls.Config{
		RootCAs: pool,
	}
	s.client = config
	return config
}

func (s *SelfSigned) ClientNoTLS() *tls.Config {
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	return config
}
