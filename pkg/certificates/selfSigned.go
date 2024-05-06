package certificates

import (
	"crypto/tls"
	"net/http"
)

type SelfSigned struct {
	transport *http.Transport
	server    *tls.Config
	client    *tls.Config
	ca        *certificate
	cert      *certificate
}

func NewSelfSigned() *SelfSigned {
	return &SelfSigned{}
}

func (s *SelfSigned) CA() *certificate {
	return s.ca
}

func (s *SelfSigned) Cert() *certificate {
	return s.cert
}

func (s *SelfSigned) ConfigTLSServer() *tls.Config {
	return s.server
}

func (s *SelfSigned) ConfigTLSClient() *tls.Config {
	return s.client
}

func (s *SelfSigned) Transport() *http.Transport {
	return s.transport
}
