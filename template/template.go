package template

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"

	"github.com/google/go-tpm/tpm2"
)

func ECDHToTPMTPublic(pubkey *ecdh.PublicKey, sha tpm2.TPMAlgID) *tpm2.TPMTPublic {
	var ecc tpm2.TPMECCCurve
	switch pubkey.Curve() {
	case ecdh.P256():
		ecc = tpm2.TPMECCNistP256
	case ecdh.P384():
		ecc = tpm2.TPMECCNistP384
	case ecdh.P521():
		ecc = tpm2.TPMECCNistP521
	}
	x, y, err := tpm2.ECCPoint(pubkey)
	if err != nil {
		panic(err)
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
					Buffer: x.Bytes(),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: y.Bytes(),
				},
			},
		),
	}
}

func EcdsaToTPMTPublic(pubkey *ecdsa.PublicKey, sha tpm2.TPMAlgID) *tpm2.TPMTPublic {
	pk, err := pubkey.ECDH()
	if err != nil {
		panic(err)
	}
	return ECDHToTPMTPublic(pk, sha)
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
