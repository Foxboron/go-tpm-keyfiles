package keyfile

import (
	encasn1 "encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// id-tpmkey OBJECT IDENTIFIER ::=
	//   {joint-iso-itu-t(2) international-organizations(23) 133 10 1}
	// Probably not used, but here for reference
	oidTPMKey = encasn1.ObjectIdentifier{2, 23, 133, 10, 2}

	OIDOldLoadableKey = encasn1.ObjectIdentifier{2, 23, 133, 10, 2}

	// id-loadablekey OBJECT IDENTIFIER ::=  {id-tpmkey 3}
	OIDLoadableKey = encasn1.ObjectIdentifier{2, 23, 133, 10, 1, 3}

	// id-importablekey OBJECT IDENTIFIER ::=  {id-tpmkey 4}
	OIDImportbleKey = encasn1.ObjectIdentifier{2, 23, 133, 10, 1, 4}

	// id-sealedkey OBJECT IDENTIFIER ::= {id-tpmkey 5}
	OIDSealedKey = encasn1.ObjectIdentifier{2, 23, 133, 10, 1, 5}
)

func readOptional(der *cryptobyte.String, tag int) (out cryptobyte.String, ok bool) {
	der.ReadOptionalASN1(&out, &ok, asn1.Tag(tag).ContextSpecific().Constructed())
	return
}

func parseTPMPolicy(der *cryptobyte.String) ([]*TPMPolicy, error) {
	var tpmpolicies []*TPMPolicy

	//   policy      [1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL,
	policy, ok := readOptional(der, 1)
	if !ok {
		return []*TPMPolicy{}, nil
	}

	// read outer sequence
	var policySequence cryptobyte.String
	if !policy.ReadASN1(&policySequence, asn1.SEQUENCE) {
		return nil, errors.New("malformed policy sequence")
	}

	for !policySequence.Empty() {
		// TPMPolicy ::= SEQUENCE
		var policyBytes cryptobyte.String
		if !policySequence.ReadASN1(&policyBytes, asn1.SEQUENCE) {
			return nil, errors.New("malformed policy sequence")
		}

		//   commandCode   [0] EXPLICIT INTEGER,
		var ccBytes cryptobyte.String
		if !policyBytes.ReadASN1(&ccBytes, asn1.Tag(0).ContextSpecific().Constructed()) {
			return nil, errors.New("strip tag from commandCode")
		}

		var tpmpolicy TPMPolicy
		if !ccBytes.ReadASN1Integer(&tpmpolicy.commandCode) {
			return nil, errors.New("malformed policy commandCode")
		}

		//   commandPolicy [1] EXPLICIT OCTET STRING
		var cpBytes cryptobyte.String
		if !policyBytes.ReadASN1(&cpBytes, asn1.Tag(1).ContextSpecific().Constructed()) {
			return nil, errors.New("strip tag from commandPolicy")
		}

		if !cpBytes.ReadASN1Bytes(&tpmpolicy.commandPolicy, asn1.OCTET_STRING) {
			return nil, errors.New("malformed policy commandPolicy")
		}
		tpmpolicies = append(tpmpolicies, &tpmpolicy)
	}
	return tpmpolicies, nil
}

func parseTPMAuthPolicy(der *cryptobyte.String) ([]*TPMAuthPolicy, error) {
	var authPolicy []*TPMAuthPolicy
	var sAuthPolicy cryptobyte.String

	//   authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL,
	sAuthPolicy, ok := readOptional(der, 3)
	if !ok {
		return authPolicy, nil
	}

	// read outer sequence
	var authPolicySequence cryptobyte.String
	if !sAuthPolicy.ReadASN1(&authPolicySequence, asn1.SEQUENCE) {
		return nil, errors.New("malformed auth policy sequence")
	}

	for !authPolicySequence.Empty() {
		// TPMAuthPolicy ::= SEQUENCE
		var authPolicyBytes cryptobyte.String
		if !authPolicySequence.ReadASN1(&authPolicyBytes, asn1.SEQUENCE) {
			return nil, errors.New("malformed auth policy sequence")
		}

		var tpmAuthPolicy TPMAuthPolicy

		//   name    [0] EXPLICIT UTF8String OPTIONAL,
		nameBytes, ok := readOptional(&authPolicyBytes, 0)
		if ok {
			var nameB cryptobyte.String
			if !nameBytes.ReadASN1(&nameB, asn1.UTF8String) {
				return nil, errors.New("malformed utf8string in auth policy name")
			}
			if !utf8.Valid(nameB) {
				return nil, errors.New("invalid utf8 bytes in name of auth policy")
			}
			tpmAuthPolicy.name = string(nameB)
		}

		//   policy  [1] EXPLICIT SEQUENCE OF TPMPolicy
		tpmpolicies, err := parseTPMPolicy(&authPolicyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed parsing tpm policies in auth policy: %v", err)
		}
		if len(tpmpolicies) == 0 {
			return nil, errors.New("tpm policies in auth policy is empty")
		}
		tpmAuthPolicy.policy = tpmpolicies

		authPolicy = append(authPolicy, &tpmAuthPolicy)
	}

	return authPolicy, nil
}

func Parse(b []byte) (*TPMKey, error) {
	var tkey TPMKey
	var err error

	// TPMKey ::= SEQUENCE
	s := cryptobyte.String(b)
	if !s.ReadASN1(&s, asn1.SEQUENCE) {
		return nil, errors.New("no sequence")
	}

	//   type        TPMKeyType,
	var oid encasn1.ObjectIdentifier
	if !s.ReadASN1ObjectIdentifier(&oid) {
		return nil, errors.New("no contentinfo oid")
	}

	// Check if we know the keytype
	// TPMKeyType ::= OBJECT IDENTIFIER (
	//   id-loadablekey |
	//   id-importablekey |
	//   id-sealedkey
	// )
	switch {
	case oid.Equal(OIDLoadableKey):
		fallthrough
	case oid.Equal(OIDImportbleKey):
		fallthrough
	case oid.Equal(OIDSealedKey):
		fallthrough
	case oid.Equal(OIDOldLoadableKey):
		tkey.keytype = oid
	default:
		return nil, errors.New("unknown key type")
	}

	//   emptyAuth   [0] EXPLICIT BOOLEAN OPTIONAL,
	if emptyAuthbytes, ok := readOptional(&s, 0); ok {
		var auth bool
		if !emptyAuthbytes.ReadASN1Boolean(&auth) {
			return nil, errors.New("no emptyAuth bool")
		}
		tkey.emptyAuth = auth
	}

	policy, err := parseTPMPolicy(&s)
	if err != nil {
		return nil, fmt.Errorf("failed reading TPMPolicy: %v", err)
	}
	tkey.policy = policy

	//   secret      [2] EXPLICIT OCTET STRING OPTIONAL,
	if secretbytes, ok := readOptional(&s, 2); ok {
		var secret cryptobyte.String
		if !secretbytes.ReadASN1(&secret, asn1.OCTET_STRING) {
			return nil, errors.New("could not parse secret")
		}
		tkey.secret = secret
	}

	//   authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL,
	authPolicy, err := parseTPMAuthPolicy(&s)
	if err != nil {
		return nil, fmt.Errorf("failed reading TPMAuthPolicy: %v", err)
	}
	tkey.authPolicy = authPolicy

	//   description  [4] EXPLICIT OCTET STRING OPTIONAL,
	if descriptionBytes, ok := readOptional(&s, 4); ok {
		var description cryptobyte.String
		if !descriptionBytes.ReadASN1(&description, asn1.UTF8String) {
			return nil, errors.New("could not parse description bytes")
		}
		if !utf8.Valid(description) {
			return nil, errors.New("description is not a valid UTF8 string")
		}
		tkey.description = string(description)
	}

	//   parent      INTEGER,
	var parent int
	if !s.ReadASN1Integer(&parent) {
		return nil, errors.New("failed reading parent")
	}
	tkey.Parent = tpm2.TPMHandle(parent)

	//   pubkey      OCTET STRING,
	var pubkey cryptobyte.String
	if !s.ReadASN1(&pubkey, asn1.OCTET_STRING) {
		return nil, errors.New("could not parse pubkey")
	}

	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubkey)
	if err != nil {
		return nil, errors.New("could not parse public section of key 1")
	}
	publicT, err := public.Contents()
	if err != nil {
		return nil, errors.New("could not parse public section of key 2")
	}
	tkey.Pubkey = *publicT

	//   privkey     OCTET STRING
	var privkey cryptobyte.String
	if !s.ReadASN1(&privkey, asn1.OCTET_STRING) {
		return nil, errors.New("could not parse privkey")
	}
	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privkey)
	if err != nil {
		return nil, errors.New("could not parse public section of key")
	}
	tkey.Privkey = *private

	return &tkey, nil
}

func Marshal(key *TPMKey) ([]byte, error) {
	var b cryptobyte.Builder

	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

		b.AddASN1ObjectIdentifier(key.keytype)

		if key.emptyAuth {
			b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1Boolean(true)
			})
		}

		if len(key.policy) != 0 {
			b.AddASN1(asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for _, policy := range key.policy {
						b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
							b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
								b.AddASN1Int64(int64(policy.commandCode))
							})
							b.AddASN1(asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
								b.AddASN1OctetString(policy.commandPolicy)
							})
						})
					}
				})
			})
		}

		if len(key.secret) != 0 {
			b.AddASN1(asn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1OctetString(key.secret)
			})
		}

		if len(key.authPolicy) != 0 {
			b.AddASN1(asn1.Tag(3).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for _, authpolicy := range key.authPolicy {
						b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
							if authpolicy.name != "" {
								b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
									b.AddASN1(asn1.UTF8String, func(b *cryptobyte.Builder) {
										// TODO: Is this correct?
										b.AddBytes([]byte(authpolicy.name))
									})
								})
							}
							// Copy of the policy writing
							b.AddASN1(asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
								b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
									for _, policy := range authpolicy.policy {
										b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
											b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
												b.AddASN1Int64(int64(policy.commandCode))
											})
											b.AddASN1(asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
												b.AddASN1OctetString(policy.commandPolicy)
											})
										})
									}
								})
							})
						})
					}
				})
			})
		}

		if len(key.description) != 0 {
			b.AddASN1(asn1.Tag(4).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(asn1.UTF8String, func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(key.description))
				})
			})
		}

		b.AddASN1Int64(int64(key.Parent))
		pubbytes := tpm2.New2B(key.Pubkey)
		b.AddASN1OctetString(tpm2.Marshal(pubbytes))
		b.AddASN1OctetString(tpm2.Marshal(key.Privkey))
	})

	return b.Bytes()
}

// Errors
var (
	ErrNotTPMKey = errors.New("not a TSS2 PRIVATE KEY")
)

var (
	pemType = "TSS2 PRIVATE KEY"
)

func Encode(key *TPMKey) ([]byte, error) {
	bytes, err := Marshal(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: bytes,
	}), nil
}

func Decode(b []byte) (*TPMKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("not an armored key")
	}
	switch block.Type {
	case pemType:
		return Parse(block.Bytes)
	default:
		return nil, ErrNotTPMKey
	}
}
