package keyfile_test

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	. "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// createPersistentParent creates a persistent handle with optional password authentication
func createPersistentParent(t *testing.T, tpm transport.TPMCloser, handle tpm2.TPMHandle, password []byte) {
	t.Helper()

	cleanupPersistentParent(t, tpm, handle, password)

	createPrimaryRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: password},
			},
		},
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("failed to create primary key: %v", err)
	}

	authHandle := tpm2.AuthHandle{
		Handle: createPrimaryRsp.ObjectHandle,
		Name:   createPrimaryRsp.Name,
	}
	if len(password) != 0 {
		authHandle.Auth = tpm2.PasswordAuth(password)
	}
	_, err = tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     authHandle,
		PersistentHandle: handle,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("failed to evict control: %v", err)
	}

	_, err = tpm2.FlushContext{FlushHandle: createPrimaryRsp.ObjectHandle}.Execute(tpm)
	if err != nil {
		t.Fatalf("failed to flush context: %v", err)
	}
}

// cleanupPersistentParent removes a persistent handle
func cleanupPersistentParent(t *testing.T, tpm transport.TPMCloser, handle tpm2.TPMHandle, password []byte) {
	t.Helper()
	readPublicRsp, err := tpm2.ReadPublic{ObjectHandle: handle}.Execute(tpm)
	if err == nil {
		authHandle := tpm2.AuthHandle{
			Handle: handle,
			Name:   readPublicRsp.QualifiedName,
			Auth:   tpm2.PasswordAuth(password),
		}
		_, _ = tpm2.EvictControl{
			Auth:             tpm2.TPMRHOwner,
			ObjectHandle:     authHandle,
			PersistentHandle: handle,
		}.Execute(tpm)
	}
}

func TestTPMKeySignerWithPersistentParent(t *testing.T) {
	cases := []struct {
		name           string
		parentPassword []byte
		childPassword  []byte
	}{
		{"password on both parent and child", []byte("parent_pass"), []byte("child_pass")},
		{"password on parent, no password on child", []byte("parent_pass"), []byte("")},
		{"password on child, no password on parent", []byte(""), []byte("child_pass")},
		{"no password on either", []byte(""), []byte("")},
	}

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	const parentHandle tpm2.TPMHandle = 0x8100000A

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			createPersistentParent(t, tpm, parentHandle, c.parentPassword)
			defer cleanupPersistentParent(t, tpm, parentHandle, c.parentPassword)

			childKey, err := NewLoadableKey(
				tpm, tpm2.TPMAlgRSA, 2048, c.parentPassword,
				WithParent(parentHandle),
				WithUserAuth(c.childPassword),
				WithDescription("test key"),
			)
			if err != nil {
				t.Fatalf("failed to create child key: %v", err)
			}

			signer := NewTPMKeySigner(
				childKey,
				func() ([]byte, error) { return c.parentPassword, nil },
				func() transport.TPMCloser { return tpm },
				func(*TPMKey) ([]byte, error) { return c.childPassword, nil },
			)

			testMessage := []byte("test message for signing")
			h := sha256.New()
			h.Write(testMessage)
			digest := h.Sum(nil)

			signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
			if err != nil {
				t.Fatalf("failed to sign with TPMKeySigner: %v", err)
			}

			if len(signature) == 0 {
				t.Error("signature is empty")
			}

			ok, err := childKey.Verify(crypto.SHA256, digest, signature)
			if err != nil {
				t.Fatalf("failed to verify signature: %v", err)
			}
			if !ok {
				t.Error("failed to verify signature")
			}
		})
	}
}
