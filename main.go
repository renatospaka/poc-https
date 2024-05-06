package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
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

	// testa abrindo uma conexão https, chamando uma rota padrão
	usingHttpServer(serverTLSConf)
}

func helloWorld(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello World!")
}

func usingHttptest(serverTLSConf, clientTLSConf *tls.Config) {
	return

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
		log.Println(body)
	} else {
		log.Println("not successful!")
	}
}

func usingHttpServer(serverTLSConf *tls.Config) {
	http.HandleFunc("/", helloWorld)

	porta := 9000
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", porta),
		Handler:   nil,
		TLSConfig: serverTLSConf,
	}

	log.Printf("servindo na porta local :%d\n", porta)
	log.Fatal(server.ListenAndServeTLS("", ""))
}
