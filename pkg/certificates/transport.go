package certificates

import "net/http"

func (s *SelfSigned) TransportNoTLS() *http.Transport {
	return &http.Transport{
		TLSClientConfig: s.ClientNoTLS(),
	}
}

func (s *SelfSigned) TransportTLS() *http.Transport {
	s.SetupClientTLSConfig()
	t := s.transport
	t.TLSClientConfig = s.ClientTLS()
	return t
}
