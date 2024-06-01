package keyfile

import (
	"encoding/asn1"

	"github.com/google/go-tpm/tpm2"
)

type TPMKeyOption func(key *TPMKey)

func WithKeytype(keytype asn1.ObjectIdentifier) TPMKeyOption {
	return func(key *TPMKey) {
		key.Keytype = keytype
	}
}

func WithPolicy(policy []*TPMPolicy) TPMKeyOption {
	return func(key *TPMKey) {
		key.Policy = policy
	}
}

func WithSecret(secret []byte) TPMKeyOption {
	return func(key *TPMKey) {
		if len(secret) == 0 {
			key.EmptyAuth = true
			return
		}
		key.Secret = secret
		key.EmptyAuth = false
	}
}

func WithDescription(desc string) TPMKeyOption {
	return func(key *TPMKey) {
		key.Description = desc
	}
}

func WithParent(parent tpm2.TPMHandle) TPMKeyOption {
	return func(key *TPMKey) {
		key.Parent = parent
	}
}

func WithAuthPolicy(authpolicy []*TPMAuthPolicy) TPMKeyOption {
	return func(key *TPMKey) {
		key.AuthPolicy = authpolicy
	}
}

func WithPubkey(pubkey tpm2.TPM2BPublic) TPMKeyOption {
	return func(key *TPMKey) {
		key.Pubkey = pubkey
	}
}

func WithPrivkey(privkey tpm2.TPM2BPrivate) TPMKeyOption {
	return func(key *TPMKey) {
		key.Privkey = privkey
	}
}
