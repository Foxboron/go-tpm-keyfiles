package keyfile

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func MkECDSA(t *testing.T, a elliptic.Curve) ecdsa.PrivateKey {
	t.Helper()
	pk, err := ecdsa.GenerateKey(a, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}
	return *pk
}

func TestImportableKey(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed creating simulator")
	}
	defer tpm.Close()

	sess := NewTPMSession(tpm)

	ecc := MkECDSA(t, elliptic.P256())

	_, srkpub, err := CreateSRK(sess, tpm2.TPMRHOwner, []byte(""))
	if err != nil {
		t.Fatalf("failed creating srk: %v", err)
	}

	key, err := NewImportablekey(srkpub, ecc)
	if err != nil {
		t.Fatalf("importkey: %v", err)
	}

	k, err := ImportTPMKey(tpm, key, []byte(nil))
	if err != nil {
		t.Fatalf("%v", err)
	}

	signer, err := k.Signer(tpm, []byte(""), []byte(""))
	if err != nil {
		t.Fatalf("couldn't create signer: %v", err)
	}

	h := crypto.SHA256.New()
	h.Write([]byte("heyho"))
	b := h.Sum(nil)

	sig, err := signer.Sign((io.Reader)(nil), b[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("failed signing: %v", err)
	}

	ok, err := k.Verify(crypto.SHA256, b[:], sig)
	if !ok || err != nil {
		t.Fatalf("invalid signature")
	}
}
