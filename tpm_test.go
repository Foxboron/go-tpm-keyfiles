package keyfile_test

import (
	"crypto"
	"io"
	"testing"

	. "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/go-tpm-keyfiles/internal/keytest"
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
			pub, priv, err := CreateKey(sess, c.alg, c.bits, []byte(""), []byte(""))
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
			handle, _, err := LoadKey(sess, k, []byte(""))
			if err != nil {
				t.Fatalf("failed loading key: %v", err)
			}
			FlushHandle(tpm, handle)
			sess.FlushHandle()
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
			pub, priv, err := CreateKey(sess, c.alg, c.bits, ownerPassword, []byte(""))
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
			handle, _, err := LoadKey(sess, k, ownerPassword)
			if err != nil {
				t.Errorf("failed loading key: %v", err)
			}
			FlushHandle(tpm, handle)
			sess.FlushHandle()
		})
	}
}

func TestChangeAuth(t *testing.T) {
	cases := []struct {
		text    string
		alg     tpm2.TPMAlgID
		bits    int
		f       keytest.KeyFunc
		oldPin  []byte
		newPin  []byte
		wanterr error
	}{
		{
			text:   "change pin",
			alg:    tpm2.TPMAlgECC,
			bits:   256,
			f:      keytest.MkKey,
			oldPin: []byte("123"),
			newPin: []byte("heyho"),
		},
		{
			text:   "change pin - empty to something",
			alg:    tpm2.TPMAlgECC,
			bits:   256,
			f:      keytest.MkImportableToLoadableKey,
			oldPin: []byte(""),
			newPin: []byte("heyho"),
		},
	}

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	for _, c := range cases {
		t.Run(c.text, func(t *testing.T) {
			k, err := c.f(t, tpm, c.alg, c.bits, []byte(""), c.oldPin, "")
			if err != nil {
				t.Fatalf("failed key import: %v", err)
			}

			h := crypto.SHA256.New()
			h.Write([]byte(c.text))
			b := h.Sum(nil)

			signer, err := k.Signer(tpm, []byte(""), c.oldPin)
			if err != nil {
				t.Fatalf("failed creating signer")
			}
			_, err = signer.Sign((io.Reader)(nil), b, crypto.SHA256)
			if err != nil {
				t.Fatalf("signing with correct pin should not fail: %v", err)
			}

			if err := ChangeAuth(tpm, []byte(""), k, c.oldPin, c.newPin); err != nil {
				t.Fatalf("ChangeAuth shouldn't fail: %v", err)
			}

			signer, err = k.Signer(tpm, []byte(""), c.oldPin)
			if err != nil {
				t.Fatalf("failed creating signer")
			}

			_, err = signer.Sign((io.Reader)(nil), b, crypto.SHA256)
			if err == nil {
				t.Fatalf("old pin works on updated key")
			}

			signer, err = k.Signer(tpm, []byte(""), c.newPin)
			if err != nil {
				t.Fatalf("failed creating signer")
			}
			_, err = signer.Sign((io.Reader)(nil), b, crypto.SHA256)
			if err != nil {
				t.Fatalf("new pin doesn't work: %v", err)
			}
		})
	}
}
