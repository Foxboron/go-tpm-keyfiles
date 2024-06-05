package keyfile

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"testing"

	swtpm "github.com/foxboron/swtpm_test"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func mustOpen(s string) []byte {
	b, err := os.ReadFile(s)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func TestParse(t *testing.T) {
	for n, tt := range []struct {
		name string
		f    []byte
	}{
		{
			name: "plain rsa key",
			f:    mustOpen("./testdata/rsa-key.tpm"),
		},
		{
			name: "plain rsa key with password",
			f:    mustOpen("./testdata/rsa-tpm-password.tpm"),
		},
		{
			name: "p256 with authvalue",
			f:    mustOpen("./testdata/p256-authvalue.tpm"),
		},
		{
			name: "sealed key",
			f:    mustOpen("./testdata/skey.tpm"),
		},
	} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			k, err := Decode(tt.f)
			if err != nil {
				t.Fatalf("failed parsing: %v", err)
			}

			if !bytes.Equal(k.Bytes(), tt.f) {
				t.Fatalf("not equal")
			}
		})
	}
}

func must2BPrivate(data []byte) tpm2.TPM2BPrivate {
	return tpm2.TPM2BPrivate{
		Buffer: data,
	}
}

func TestEncodeDecode(t *testing.T) {
	for n, tt := range []struct {
		*TPMKey
	}{
		{
			&TPMKey{
				Keytype:     OIDLoadableKey,
				EmptyAuth:   true,
				Description: "test",
				Parent:      tpm2.TPMHandle(0x40000001),
				Pubkey:      tpm2.New2B(tpm2.ECCSRKTemplate),
				Privkey:     must2BPrivate([]byte("some data")),
			},
		},
	} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			key, err := Decode(tt.TPMKey.Bytes())
			if err != nil {
				t.Fatalf("failed decoding key: %v", err)
			}
			if !tt.TPMKey.Keytype.Equal(key.Keytype) {
				t.Fatalf("tpmkey keytype is not equal")
			}

			if tt.TPMKey.EmptyAuth != key.EmptyAuth {
				t.Fatalf("tpmkey emptyAuth is not equal")
			}

			if tt.TPMKey.Description != key.Description {
				t.Fatalf("tpmkey description is not equal")
			}

			if tt.TPMKey.Parent != key.Parent {
				t.Fatalf("tpmkey parent is not equal")
			}

			if !bytes.Equal(tpm2.Marshal(tt.TPMKey.Pubkey), tpm2.Marshal(key.Pubkey)) {
				t.Fatalf("tpmkey pubkey is not equal")
			}

			if !bytes.Equal(tt.TPMKey.Privkey.Buffer, key.Privkey.Buffer) {
				t.Fatalf("tpmkey pivkey is not equal")
			}
		})
	}
}

type OpenSSLKey struct {
	algorithm string
	pkeyopt   []string
}

func mkProviderKey(t *testing.T, socket string, k *OpenSSLKey) string {
	t.Helper()

	args := []string{
		"genpkey", "-provider", "tpm2",
	}

	dir := t.TempDir()
	filename := path.Join(dir, "testkey.priv")

	args = append(args, "-algorithm", k.algorithm)

	if len(k.pkeyopt) != 0 {
		for _, s := range k.pkeyopt {
			args = append(args, "-pkeyopt", s)
		}
	}

	args = append(args, "-out", filename)

	cmd := exec.Command("openssl", args...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TPM2OPENSSL_TCTI=swtpm:path=%s", socket),
	)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		panic(err)
	}
	err = cmd.Wait()
	if err != nil {
		panic(err)
	}
	return filename
}

func TestOpenSSLKeys(t *testing.T) {
	dir := t.TempDir()

	swtpm := swtpm.NewSwtpm(dir)
	socket, err := swtpm.Socket()
	if err != nil {
		t.Fatalf("failed socket: %v", err)
	}
	defer swtpm.Close()

	tpm, err := transport.OpenTPM(socket)
	if err != nil {
		t.Fatalf("failed opentpm: %v", err)
	}
	defer tpm.Close()

	for _, tt := range []struct {
		name     string
		k        *OpenSSLKey
		userauth []byte
		wantErr  error
	}{
		{
			name: "rsa - test sign",
			k: &OpenSSLKey{
				algorithm: "RSA",
			},
			wantErr: nil,
		},
		{
			name: "ecdsa p256 - test sign",
			k: &OpenSSLKey{
				algorithm: "EC",
				pkeyopt:   []string{"group:P-256"},
			},
			wantErr: nil,
		},
		{
			name: "ecdsa p256 - with user auth in creation",
			k: &OpenSSLKey{
				algorithm: "EC",
				pkeyopt:   []string{"group:P-256", "user-auth:abc"},
			},
			wantErr: tpm2.TPMRCAuthFail,
		},
		{
			name: "ecdsa p256 - with user auth",
			k: &OpenSSLKey{
				algorithm: "EC",
				pkeyopt:   []string{"group:P-256", "user-auth:abc"},
			},
			userauth: []byte("abc"),
			wantErr:  nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {

			filename := mkProviderKey(t, socket, tt.k)

			b, err := os.ReadFile(filename)
			if err != nil {
				t.Fatalf("failed reading file: %v", err)
			}

			key, err := Decode(b)
			if err != nil {
				t.Fatalf("failed key decode: %v", err)
			}

			signer, err := key.Signer(tpm, []byte(""), tt.userauth)
			if err != nil {
				t.Fatalf("failed making signer: %v", err)
			}

			h := crypto.SHA256.New()
			h.Write([]byte("message"))
			b = h.Sum(nil)

			sig, err := signer.Sign((io.Reader)(nil), b[:], crypto.SHA256)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("failed signing: %v", err)
			}

			if tt.wantErr == nil {
				ok, err := key.Verify(crypto.SHA256, b[:], sig)
				if !ok || err != nil {
					t.Fatalf("failed signature verification: %v", err)
				}
			}
		})
	}
}
