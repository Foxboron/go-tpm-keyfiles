package template

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"

	"github.com/google/go-tpm/tpm2"
)

func EcdsaToTPMTPublic(pubkey *ecdsa.PublicKey, sha tpm2.TPMAlgID) *tpm2.TPMTPublic {
	var ecc tpm2.TPMECCCurve
	switch pubkey.Curve {
	case elliptic.P256():
		ecc = tpm2.TPMECCNistP256
	case elliptic.P384():
		ecc = tpm2.TPMECCNistP384
	case elliptic.P521():
		ecc = tpm2.TPMECCNistP521
	}
	return &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: sha,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:  true,
			UserWithAuth: true,
			Decrypt:      true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: ecc,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: pubkey.X.FillBytes(make([]byte, len(pubkey.X.Bytes()))),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: pubkey.Y.FillBytes(make([]byte, len(pubkey.X.Bytes()))),
				},
			},
		),
	}
}

func RSAToTPMTPublic(pubkey *rsa.PublicKey, bits int) *tpm2.TPMTPublic {
	return &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:  true,
			UserWithAuth: true,
			Decrypt:      true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				KeyBits: tpm2.TPMKeyBits(bits),
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{Buffer: pubkey.N.Bytes()},
		),
	}
}
