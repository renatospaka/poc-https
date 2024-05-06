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
	c := certificates.NewSelfSigned()

	// configuração do certificador CA
	err := c.SetupCA()
	if err != nil {
		panic(err)
	}

	// configuração do certificado do Servidor
	err = c.SetupCert()
	if err != nil {
		panic(err)
	}

	// retorna as configurações TLS do servidor e do cliente
	serverTLSConf := c.ConfigTLSServer()
	clientTLSConf := c.ConfigTLSClient()

	// testa usando httptest
	usingHttptest(serverTLSConf, clientTLSConf)
}

func usingHttptest(serverTLSConf, clientTLSConf *tls.Config) {
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
