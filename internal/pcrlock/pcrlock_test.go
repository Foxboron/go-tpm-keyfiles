package pcrlock

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

func GetSRKPrimary(rwc transport.TPMCloser) (*tpm2.NamedHandle, *tpm2.TPMTPublic, error) {
	handel := tpm2.TPMHandle(0x81000001)
	rsp, err := tpm2.ReadPublic{
		ObjectHandle: handel,
	}.Execute(rwc)
	if err != nil {
		return nil, nil, err
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}
	return &tpm2.NamedHandle{
		Handle: handel,
		Name:   rsp.Name,
	}, pub, nil
}

func TestPcrLockParse(t *testing.T) {
	secret := []byte("lol this is a test")

	b, err := os.ReadFile("test/pcrlock.json")
	if err != nil {
		t.Fatalf("can't read file")
	}
	policy, err := ParsePolicy(b)
	if err != nil {
		t.Fatalf("failed to parse pcrlock policy: %v", err)
	}
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		log.Fatal(err)
	}
	defer tpm.Close()

	rsp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(policy.NVIndex),
	}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}

	pol, _, err := policy.Policy()
	if err != nil {
		t.Fatalf("creating policy calculator: %v", err)
	}

	authNVCmd := tpm2.PolicyAuthorizeNV{
		NVIndex: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(policy.NVIndex),
			Name:   rsp.NVName,
		},
	}
	if err = authNVCmd.Update(pol); err != nil {
		t.Fatalf("error updating policy calculator: %v", err)
	}
	digest := pol.Hash().Digest

	sealBlobCmd, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x81000001),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: secret,
				}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:       tpm2.TPMAlgKeyedHash,
			NameAlg:    tpm2.TPMAlgSHA256,
			AuthPolicy: tpm2.TPM2BDigest{Buffer: digest},
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: false,
				NoDA:         true,
			},
		}),
	}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(sealBlobCmd)
	fmt.Println("yes?")

	sess, cleanup1, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer func() {
		cleanup1()
	}()

	_, _, err = policy.GetPolicySession(tpm, sess)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tpm2.PolicyAuthorizeNV{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(policy.NVIndex),
			Name:   rsp.NVName,
		},
		PolicySession: sess.Handle(),
	}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}

	loadrsp, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x81000001),
		},
		InPublic:  sealBlobCmd.OutPublic,
		InPrivate: sealBlobCmd.OutPrivate,
	}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}

	unsealCmd, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadrsp.ObjectHandle,
			Name:   loadrsp.Name,
			Auth:   sess,
		},
	}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}

	tpm2.FlushContext{
		FlushHandle: loadrsp.ObjectHandle,
	}.Execute(tpm)

	if !bytes.Equal(secret, unsealCmd.OutData.Buffer) {
		t.Fatal("secret and unsealed secret is different")
	}
}

func TestCreatePolicy(t *testing.T) {
	b, err := os.ReadFile("test/pcrlock.json")
	if err != nil {
		t.Fatalf("can't read file")
	}
	policy, err := ParsePolicy(b)
	if err != nil {
		t.Fatalf("failed to parse pcrlock policy: %v", err)
	}

	_, pp, err := policy.Policy()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%x\n", pp)
}
