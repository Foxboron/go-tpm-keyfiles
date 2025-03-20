package keyfile

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPMKeySigner implements the crypto.Signer interface for TPMKey
// It allows passing callbacks for TPM, ownerAuth and user auth.
type TPMKeySigner struct {
	key       *TPMKey
	ownerAuth func() ([]byte, error)
	tpm       func() transport.TPMCloser
	auth      func(*TPMKey) ([]byte, error)
}

var _ crypto.Signer = &TPMKeySigner{}

// Returns the crypto.PublicKey
func (t *TPMKeySigner) Public() crypto.PublicKey {
	pk, err := t.key.PublicKey()
	// This shouldn't happen!
	if err != nil {
		panic(fmt.Errorf("failed producing public: %v", err))
	}
	return pk
}

// Sign implementation
func (t *TPMKeySigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var digestalg, signalg tpm2.TPMAlgID

	auth := []byte("")
	if t.key.HasAuth() {
		p, err := t.auth(t.key)
		if err != nil {
			return nil, err
		}
		auth = p
	}

	switch opts.HashFunc() {
	case crypto.SHA256:
		digestalg = tpm2.TPMAlgSHA256
	case crypto.SHA384:
		digestalg = tpm2.TPMAlgSHA384
	case crypto.SHA512:
		digestalg = tpm2.TPMAlgSHA512
	default:
		return nil, fmt.Errorf("%s is not a supported hashing algorithm", opts.HashFunc())
	}

	signalg = t.key.KeyAlgo()
	if _, ok := opts.(*rsa.PSSOptions); ok {
		if signalg != tpm2.TPMAlgRSA {
			return nil, fmt.Errorf("Attempting to use PSSOptions with non-RSA (alg %x) key", signalg)
		}
		signalg = tpm2.TPMAlgRSAPSS
	}

	ownerauth, err := t.ownerAuth()
	if err != nil {
		return nil, err
	}

	sess := NewTPMSession(t.tpm())
	sess.SetTPM(t.tpm())

	return SignASN1(sess, t.key, ownerauth, auth, digest, digestalg, signalg)
}

func NewTPMKeySigner(k *TPMKey, ownerAuth func() ([]byte, error), tpm func() transport.TPMCloser, auth func(*TPMKey) ([]byte, error)) *TPMKeySigner {
	return &TPMKeySigner{
		key:       k,
		ownerAuth: ownerAuth,
		tpm:       tpm,
		auth:      auth,
	}
}
