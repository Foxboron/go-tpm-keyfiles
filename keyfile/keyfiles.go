package keyfile

import (
	encasn1 "encoding/asn1"

	"github.com/google/go-tpm/tpm2"
)

type TPMPolicy struct {
	commandCode   int
	commandPolicy []byte
}

type TPMAuthPolicy struct {
	name   string
	policy []*TPMPolicy
}

type TPMKey struct {
	keytype     encasn1.ObjectIdentifier
	emptyAuth   bool
	policy      []*TPMPolicy
	secret      []byte
	authPolicy  []*TPMAuthPolicy
	description string
	Parent      tpm2.TPMHandle
	Pubkey      tpm2.TPM2BPublic
	Privkey     tpm2.TPM2BPrivate
}

func (t *TPMKey) HasSinger() bool {
	pub, err := t.Pubkey.Contents()
	if err != nil {
		panic("can't serialize public key")
	}
	return pub.ObjectAttributes.SignEncrypt
}

func (t *TPMKey) HasAuth() bool {
	return !t.emptyAuth
}

func (t *TPMKey) KeyAlgo() tpm2.TPMAlgID {
	pub, err := t.Pubkey.Contents()
	if err != nil {
		panic("can't serialize public key")
	}
	return pub.Type
}

func (t *TPMKey) SetDescription(s string) {
	t.description = s
}

func (t *TPMKey) Description() string {
	return t.description
}

func (t *TPMKey) Bytes() []byte {
	return Encode(t)
}

func NewLoadableKey(public tpm2.TPM2BPublic, private tpm2.TPM2BPrivate, parent tpm2.TPMHandle, emptyAuth bool) (*TPMKey, error) {
	var key TPMKey
	key.keytype = OIDLoadableKey
	key.emptyAuth = emptyAuth

	key.Pubkey = public
	key.Privkey = private

	key.Parent = parent

	return &key, nil
}
