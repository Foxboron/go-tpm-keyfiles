package keytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type KeyFunc func(t *testing.T, tpm transport.TPMCloser, keytype tpm2.TPMAlgID, bits int, ownerauth []byte, userauth []byte, comment string) (*keyfile.TPMKey, error)

func MkRSA(t *testing.T, bits int) rsa.PrivateKey {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	return *pk
}

func MkECDSA(t *testing.T, a elliptic.Curve) ecdsa.PrivateKey {
	t.Helper()
	pk, err := ecdsa.GenerateKey(a, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}
	return *pk
}

// Test helper for CreateKey
func MkKey(t *testing.T, tpm transport.TPMCloser, keytype tpm2.TPMAlgID, bits int, ownerauth []byte, userauth []byte, comment string) (*keyfile.TPMKey, error) {
	t.Helper()
	return keyfile.NewLoadableKey(
		tpm, keytype, bits, []byte(nil),
		keyfile.WithUserAuth(userauth),
		keyfile.WithDescription(comment),
	)
}

// Helper to make an importable key
func MkImportableKey(t *testing.T, tpm transport.TPMCloser, keytype tpm2.TPMAlgID, bits int, ownerauth []byte, userauth []byte, comment string) (*keyfile.TPMKey, error) {
	t.Helper()
	var pk any
	switch keytype {
	case tpm2.TPMAlgECC:
		switch bits {
		case 256:
			pk = MkECDSA(t, elliptic.P256())
		case 384:
			pk = MkECDSA(t, elliptic.P384())
		case 521:
			pk = MkECDSA(t, elliptic.P521())
		}
	case tpm2.TPMAlgRSA:
		pk = MkRSA(t, bits)
	}

	// We need to always have a parent public, fetch the SRK one.
	sess := keyfile.NewTPMSession(tpm)
	h, srkpub, err := keyfile.CreateSRK(sess, tpm2.TPMRHOwner, []byte(""))
	if err != nil {
		t.Fatalf("failed creating srk for importable key: %v", err)
	}
	keyfile.FlushHandle(tpm, h)

	return keyfile.NewImportablekey(srkpub, pk,
		keyfile.WithUserAuth(userauth),
		keyfile.WithDescription(comment))
}

// Give us some random bytes
func MustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
