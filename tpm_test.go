package keyfile

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestCreateKey(t *testing.T) {
	cases := []struct {
		text string
		alg  tpm2.TPMAlgID
		bits int
	}{
		{
			text: "p256",
			alg:  tpm2.TPMAlgECC,
			bits: 256,
		},
		{
			text: "p384",
			alg:  tpm2.TPMAlgECC,
			bits: 384,
		},
		{
			text: "p521",
			alg:  tpm2.TPMAlgECC,
			bits: 521,
		},
		{
			text: "rsa",
			alg:  tpm2.TPMAlgRSA,
			bits: 2048,
		},
	}

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	sess := NewTPMSession(tpm)

	for _, c := range cases {
		t.Run(c.text, func(t *testing.T) {
			pub, priv, err := createKey(sess, c.alg, c.bits, []byte(""), []byte(""))
			if err != nil {
				t.Errorf("failed key creation: %v", err)
			}

			k := &TPMKey{
				Keytype:   OIDLoadableKey,
				EmptyAuth: true,
				Parent:    tpm2.TPMRHOwner,
				Pubkey:    pub,
				Privkey:   priv,
			}

			// Test if we can load the key
			// signer/signer_test.go tests the signing of the key
			handle, err := LoadKey(tpm, k, []byte(""))
			if err != nil {
				t.Fatalf("failed loading key: %v", err)
			}
			FlushHandle(tpm, handle)
		})
	}
}

func TestCreateKeyWithOwnerPassword(t *testing.T) {
	cases := []struct {
		text string
		alg  tpm2.TPMAlgID
		bits int
	}{
		{
			text: "p256",
			alg:  tpm2.TPMAlgECC,
			bits: 256,
		},
		{
			text: "p384",
			alg:  tpm2.TPMAlgECC,
			bits: 384,
		},
		{
			text: "p521",
			alg:  tpm2.TPMAlgECC,
			bits: 521,
		},
		{
			text: "rsa",
			alg:  tpm2.TPMAlgRSA,
			bits: 2048,
		},
	}
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	sess := NewTPMSession(tpm)

	ownerPassword := []byte("testPassword")

	hca := tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.TPMRHOwner,
		NewAuth: tpm2.TPM2BAuth{
			Buffer: ownerPassword,
		},
	}
	_, err = hca.Execute(tpm)
	if err != nil {
		t.Errorf("failed HierarchyChangeAuth: %v", err)
	}

	for _, c := range cases {
		t.Run(c.text, func(t *testing.T) {
			pub, priv, err := createKey(sess, c.alg, c.bits, ownerPassword, []byte(""))
			if err != nil {
				t.Errorf("failed key import: %v", err)
			}

			k := &TPMKey{
				Keytype:   OIDLoadableKey,
				EmptyAuth: true,
				Parent:    tpm2.TPMRHOwner,
				Pubkey:    pub,
				Privkey:   priv,
			}

			// Test if we can load the key
			// signer/signer_test.go tests the signing of the key
			handle, err := LoadKey(tpm, k, ownerPassword)
			if err != nil {
				t.Errorf("failed loading key: %v", err)
			}
			FlushHandle(tpm, handle)
		})
	}
}
