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

// ToTPMPublic takes a PKIX ASN.1 structure and transforms it into a
// tpm2.TPMTPublic structure
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
		// TODO: Support other bit lengths
		return template.RSAToTPMTPublic(p, 2048), nil
	default:
		return nil, fmt.Errorf("unsupported keytype")
	}
}

// FromTPMPublic takes a tpm2.TPMTPublic struct and transform it into a PKIX
// ASN.1 structure
func FromTPMPublic(pub *tpm2.TPMTPublic) ([]byte, error) {
	pk, err := template.FromTPMPublicToPubkey(pub)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(pk)
}
