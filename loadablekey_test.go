package keyfile

import (
	"crypto"
	"fmt"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestNewLoadableKey(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("message")
	}
	defer tpm.Close()
	key, err := NewLoadableKey(tpm, tpm2.TPMAlgECC, 256, []byte{},
		WithDescription("testkey"),
	)
	if err != nil {
		t.Fatalf("message")
	}
	fmt.Println(key)

}

func TestSigning(t *testing.T) {
	cases := []struct {
		msg        string
		keytype    tpm2.TPMAlgID
		bits       int
		digest     crypto.Hash
		filekey    []byte
		pin        []byte
		signpin    []byte
		shouldfail bool
	}{
		{
			msg:     "ecdsa - test encryption/decrypt - no pin",
			filekey: []byte("this is a test filekey"),
			keytype: tpm2.TPMAlgECC,
			digest:  crypto.SHA256,
			bits:    256,
		},
		{
			msg:     "ecdsa - test encryption/decrypt - pin",
			filekey: []byte("this is a test filekey"),
			pin:     []byte("123"),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgECC,
			digest:  crypto.SHA256,
			bits:    256,
		},
		{
			msg:        "ecdsa - test encryption/decrypt - no pin for sign",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
			keytype:    tpm2.TPMAlgECC,
			digest:     crypto.SHA256,
			bits:       256,
		},
		{
			msg:     "ecdsa - test encryption/decrypt - no pin for key, pin for sign",
			filekey: []byte("this is a test filekey"),
			pin:     []byte(""),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgECC,
			digest:  crypto.SHA256,
			bits:    256,
		},
		{
			msg:     "rsa - test encryption/decrypt - no pin",
			filekey: []byte("this is a test filekey"),
			keytype: tpm2.TPMAlgRSA,
			digest:  crypto.SHA256,
			bits:    2048,
		},
		{
			msg:     "rsa - test encryption/decrypt - pin",
			filekey: []byte("this is a test filekey"),
			pin:     []byte("123"),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgRSA,
			digest:  crypto.SHA256,
			bits:    2048,
		},
		{
			msg:        "rsa - test encryption/decrypt - no pin for sign",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
			keytype:    tpm2.TPMAlgRSA,
			digest:     crypto.SHA256,
			bits:       2048,
		},
		{
			msg:     "rsa - test encryption/decrypt - no pin for key, pin for sign",
			filekey: []byte("this is a test filekey"),
			pin:     []byte(""),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgRSA,
			digest:  crypto.SHA256,
			bits:    2048,
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case %d, %s", n, c.msg), func(t *testing.T) {
			// Always re-init simulator as the Signer is going to close it,
			// and we can't retain state.
			tpm, err := simulator.OpenSimulator()
			if err != nil {
				t.Fatal(err)
			}
			defer tpm.Close()

			h := c.digest.New()
			h.Write([]byte("heyho"))
			b := h.Sum(nil)

			k, err := NewLoadableKey(tpm, c.keytype, c.bits, []byte(""),
				WithUserAuth(c.pin),
			)

			if err != nil {
				t.Fatalf("couldn't create new loadable key: %v", err)
			}

			signer, err := k.Signer(tpm, []byte(""), c.signpin)
			if err != nil {
				t.Fatalf("couldn't create signer: %v", err)
			}

			sig, err := signer.Sign((io.Reader)(nil), b[:], c.digest)
			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("%v", err)
			}

			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("failed test: %v", err)
			}

			if c.shouldfail {
				t.Fatalf("test should be failing")
			}

			ok, err := k.Verify(c.digest, b[:], sig)
			if !ok || err != nil {
				t.Fatalf("invalid signature")
			}
		})
	}
}

func TestSigningWithOwnerPassword(t *testing.T) {
	ownerPassword := []byte("testPassword")

	cases := []struct {
		msg           string
		keytype       tpm2.TPMAlgID
		bits          int
		digest        crypto.Hash
		filekey       []byte
		pin           []byte
		signpin       []byte
		ownerpassword []byte
		shouldfail    bool
	}{
		{
			msg:           "ecdsa - test encryption/decrypt - no pin",
			filekey:       []byte("this is a test filekey"),
			keytype:       tpm2.TPMAlgECC,
			digest:        crypto.SHA256,
			bits:          256,
			ownerpassword: ownerPassword,
		},
		{
			msg:           "ecdsa - test encryption/decrypt - pin",
			filekey:       []byte("this is a test filekey"),
			pin:           []byte("123"),
			signpin:       []byte("123"),
			keytype:       tpm2.TPMAlgECC,
			digest:        crypto.SHA256,
			bits:          256,
			ownerpassword: ownerPassword,
		},
		{
			msg:           "ecdsa - test encryption/decrypt - no pin - invalid owner password",
			filekey:       []byte("this is a test filekey"),
			keytype:       tpm2.TPMAlgECC,
			digest:        crypto.SHA256,
			bits:          256,
			shouldfail:    true,
			ownerpassword: []byte("invalidPassword"),
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case %d, %s", n, c.msg), func(t *testing.T) {
			// Always re-init simulator as the Signer is going to close it,
			// and we can't retain state.
			tpm, err := simulator.OpenSimulator()
			if err != nil {
				t.Fatal(err)
			}
			defer tpm.Close()

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

			h := c.digest.New()
			h.Write([]byte("heyho"))
			b := h.Sum(nil)

			k, err := NewLoadableKey(tpm, c.keytype, c.bits, c.ownerpassword,
				WithUserAuth(c.pin),
			)
			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("%v", err)
			}

			signer, err := k.Signer(tpm, c.ownerpassword, c.signpin)
			if err != nil {
				t.Fatalf("couldn't create signer: %v", err)
			}

			sig, err := signer.Sign((io.Reader)(nil), b[:], c.digest)
			if err != nil {
				if c.shouldfail {
					t.Fatalf("test should be failing")
				}
				t.Fatalf("%v", err)
			}

			ok, err := k.Verify(c.digest, b[:], sig)
			if !ok || err != nil {
				t.Fatalf("invalid signature")
			}
		})
	}
}
