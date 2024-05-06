package certificates

import "errors"

var (
	ErrCertificadoCAChavePrivada   = errors.New("erro ao gerar a chave privada do CA")
	ErrCertificadoCA               = errors.New("erro ao gerar o CA")
	ErrCertificadoCAInvalido       = errors.New("CA inválido ou inexistente")
	ErrCertificadoCertChavePrivada = errors.New("erro ao gerar a chave privada do certificado")
	ErrCertificadoCert             = errors.New("erro ao gerar o certificado")
	ErrCertificadoCertInvalido     = errors.New("certificado inválido ou inexistente")
	ErrCertificadoNotPaired        = errors.New("erro ao parear o CA com o certificado")
)
