package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/renatospaka/ca-certificate/pkg/certificates"
)

func main() {
	// busca o ca e o certificado do servidor
	serverTLSConf, clientTLSConf, err := certsetup()
	if err != nil {
		panic(err)
	}

	// configura o http.Server para usar o certificado auto-assinado (CA)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "success!")
		return
	}))
	server.TLS = serverTLSConf
	server.StartTLS()
	defer server.Close()

	// comunicando com o servidor usando um http.Client configurado para confiar no CA
	transport := &http.Transport{
		TLSClientConfig: clientTLSConf,
	}
	http := http.Client{
		Transport: transport,
	}

	resp, err := http.Get(server.URL)
	if err != nil {
		panic(err)
	}

	// abre a resposta
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	body := strings.TrimSpace(string(respBodyBytes[:]))
	if body == "success!" {
		fmt.Println(body)
	} else {
		fmt.Println("not successful!")
	}
}

// Inicializa todos as chaves e certificados necessários
func certsetup() (serverTLSConf *tls.Config, clientTLSConf *tls.Config, err error) {
	c := certificates.NewSelfSigned()

	// configuração do certificador CA
	err = c.SetupCA()
	if err != nil {
		return nil, nil, err
	}
	// ca := c.CA()
	// caCert = ca.Certificate()
	// caPrivateKey = ca.PrivateKey

	// // configuração do certificador CA
	// ca := &x509.Certificate{
	// 	SerialNumber: big.NewInt(2019),
	// 	Subject: pkix.Name{
	// 		Country:            []string{"BR"},
	// 		Organization:       []string{"Goiaba LTDA"},
	// 		OrganizationalUnit: []string{},
	// 		Locality:           []string{"São Paulo"},
	// 		Province:           []string{"SP"},
	// 		StreetAddress:      []string{"Av Rio Branco, 1509"},
	// 		PostalCode:         []string{"00000-000"},
	// 	},
	// 	NotBefore:             time.Now(),
	// 	NotAfter:              time.Now().AddDate(5, 0, 0),
	// 	IsCA:                  true,
	// 	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	// 	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	// 	BasicConstraintsValid: true,
	// }

	// // criando as chaves privada e pública
	// caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	// if err != nil {
	// 	return nil, nil, err
	// }

	// // criando o CA
	// caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	// if err != nil {
	// 	return nil, nil, err
	// }

	// // PEM encode
	// caPEM := new(bytes.Buffer)
	// pem.Encode(caPEM, &pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: caBytes,
	// })

	// caPrivateKeyPEM := new(bytes.Buffer)
	// pem.Encode(caPrivateKeyPEM, &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	// })

	// configuração do certificado do Servidor
	err = c.SetupCert()
	if err != nil {
		return nil, nil, err
	}

	// retorna as configurações TLS do servidor e do cliente
	serverTLSConf = c.ConfigTLSServer()
	clientTLSConf = c.ConfigTLSServer()

	// // configuração do certificado do Servidor
	// cert := &x509.Certificate{
	// 	SerialNumber: big.NewInt(2019),
	// 	Subject: pkix.Name{
	// 		Country:            []string{"BR"},
	// 		Organization:       []string{"Goiaba LTDA"},
	// 		OrganizationalUnit: []string{},
	// 		Locality:           []string{"São Paulo"},
	// 		Province:           []string{"SP"},
	// 		StreetAddress:      []string{"Av Rio Branco, 1509"},
	// 		PostalCode:         []string{"00000-000"},
	// 	},
	// 	IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	// 	NotBefore:    time.Now(),
	// 	NotAfter:     time.Now().AddDate(5, 0, 0),
	// 	SubjectKeyId: []byte{1, 2, 3, 4, 6},
	// 	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	// 	KeyUsage:     x509.KeyUsageDigitalSignature,
	// }

	// certPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	// if err != nil {
	// 	return nil, nil, err
	// }

	// certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivateKey.PublicKey, caPrivateKey)
	// if err != nil {
	// 	return nil, nil, err
	// }

	// // PEM encode
	// certPEM := new(bytes.Buffer)
	// pem.Encode(certPEM, &pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: certBytes,
	// })

	// certPrivateKeyPEM := new(bytes.Buffer)
	// pem.Encode(certPrivateKeyPEM, &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(certPrivateKey),
	// })

	// serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivateKeyPEM.Bytes())
	// if err != nil {
	// 	return nil, nil, err
	// }

	// serverTLSConf = &tls.Config{
	// 	Certificates: []tls.Certificate{serverCert},
	// }

	// certPool := x509.NewCertPool()
	// certPool.AppendCertsFromPEM(ca.PEM().Bytes())
	// clientTLSConf = &tls.Config{
	// 	RootCAs: certPool,
	// }
	return
}
