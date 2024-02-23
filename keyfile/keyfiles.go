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
	description []byte
	Parent      tpm2.TPMHandle
	Pubkey      tpm2.TPMTPublic
	Privkey     tpm2.TPM2BPrivate
}

func (t *TPMKey) HasSinger() bool {
	return t.Pubkey.ObjectAttributes.SignEncrypt
}

func (t *TPMKey) HasAuth() bool {
	return !t.emptyAuth
}

func (t *TPMKey) KeyAlgo() tpm2.TPMAlgID {
	return t.Pubkey.Type
}

func (t *TPMKey) SetDescription(b []byte) {
	t.description = b
}

func (t *TPMKey) Description() []byte {
	return t.description
}

func NewLoadableKey(public tpm2.TPM2BPublic, private tpm2.TPM2BPrivate, parent tpm2.TPMHandle, emptyAuth bool) (*TPMKey, error) {
	var key TPMKey
	key.keytype = OIDLoadableKey
	key.emptyAuth = emptyAuth

	pub, err := public.Contents()
	if err != nil {
		return nil, err
	}
	key.Pubkey = *pub
	key.Privkey = private

	key.Parent = parent

	return &key, nil
}
