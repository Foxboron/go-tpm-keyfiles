package pkix

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/foxboron/go-tpm-keyfiles/template"
	"github.com/google/go-tpm/tpm2"
)

func ToTPMPublic(pKey []byte) (*tpm2.TPMTPublic, error) {
	block, _ := pem.Decode([]byte(pKey))

	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing pem key: %v", err)
	}

	switch p := key.(type) {
	case *ecdsa.PublicKey:
		return template.EcdsaToTPMTPublic(p, tpm2.TPMAlgSHA256), nil
	case *rsa.PublicKey:
		return template.RSAToTPMTPublic(p, 2048), nil
	default:
		return nil, fmt.Errorf("unsupported keytype")
	}
}
