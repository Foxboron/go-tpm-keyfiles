package keyfiles

import (
	encasn1 "encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// id-tpmkey OBJECT IDENTIFIER ::=
	//   {joint-iso-itu-t(2) international-organizations(23) 133 10 1}
	// Probably not used, but here for reference
	oidTPMKey = encasn1.ObjectIdentifier{2, 23, 133, 10, 2}

	// id-loadablekey OBJECT IDENTIFIER ::=  {id-tpmkey 3}
	OIDOldLoadableKey = encasn1.ObjectIdentifier{2, 23, 133, 10, 2}

	// id-importablekey OBJECT IDENTIFIER ::=  {id-tpmkey 4}
	OIDLoadableKey = encasn1.ObjectIdentifier{2, 23, 133, 10, 1, 3}

	OIDImportbleKey = encasn1.ObjectIdentifier{2, 23, 133, 10, 1, 4}

	// id-sealedkey OBJECT IDENTIFIER ::= {id-tpmkey 5}
	OIDSealedKey = encasn1.ObjectIdentifier{2, 23, 133, 10, 1, 5}
)

// Errors
var (
	ErrNotTPMKey = errors.New("not a TSS2 PRIVATE KEY")
)

func unwrapPEM(p []byte) ([]byte, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, fmt.Errorf("not an armored key")
	}
	switch block.Type {
	case "TSS2 PRIVATE KEY":
		return block.Bytes, nil
	default:
		return nil, ErrNotTPMKey
	}
}

type TPMPolicy struct {
	commandCode   int
	commandPolicy []byte
}

func ParseTPMPolicy(der *cryptobyte.String) ([]*TPMPolicy, error) {
	return nil, nil
}

type TPMAuthPolicy struct {
	name   []byte
	policy []byte
}

func ParseTPMAuthPolicy(der *cryptobyte.String) ([]*TPMAuthPolicy, error) {
	return nil, nil
}

type TPMKey struct {
	keytype    encasn1.ObjectIdentifier
	emptyAuth  bool
	policy     []*TPMPolicy
	secret     []byte
	authPolicy []*TPMAuthPolicy
	Parent     int
	Pubkey     []byte
	Privkey    []byte
}

func Parse(b []byte) (*TPMKey, error) {
	var tkey TPMKey
	var err error

	b, err = unwrapPEM(b)
	if err != nil {
		return nil, err
	}

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
	var emptyAuth cryptobyte.String
	var hasEmptyAuth bool
	if !s.ReadOptionalASN1(&emptyAuth, &hasEmptyAuth, asn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, errors.New("should have emptyAuth, failed reading")
	}
	if hasEmptyAuth {
		var auth bool
		if !emptyAuth.ReadASN1Boolean(&auth) {
			return nil, errors.New("no emptyAuth bool")
		}
		tkey.emptyAuth = auth
	}

	//   policy      [1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL,
	var sPolicy cryptobyte.String
	var hasPolicy bool
	if !s.ReadOptionalASN1(&sPolicy, &hasPolicy, asn1.Tag(1).ContextSpecific().Constructed()) {
		return nil, errors.New("should have policy, failed reading")
	}
	if hasPolicy {
		policy, err := ParseTPMPolicy(&sPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed reading TPMPolicy: %v", err)
		}
		tkey.policy = policy
	}

	//   secret      [2] EXPLICIT OCTET STRING OPTIONAL,
	var sSecret cryptobyte.String
	var hasSecret bool
	if !s.ReadOptionalASN1(&sSecret, &hasSecret, asn1.Tag(2).ContextSpecific().Constructed()) {
		return nil, errors.New("should have secret, failed reading")
	}
	if hasSecret {
		var secret cryptobyte.String
		if !sSecret.ReadASN1(&secret, asn1.OCTET_STRING) {
			return nil, errors.New("could not parse secret")
		}
		tkey.secret = secret
	}

	//   authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL,
	var sAuthPolicy cryptobyte.String
	var hasAuthPolicy bool
	if !s.ReadOptionalASN1(&sAuthPolicy, &hasAuthPolicy, asn1.Tag(3).ContextSpecific().Constructed()) {
		return nil, errors.New("should have authPolicy, failed reading")
	}
	if hasAuthPolicy {
		authPolicy, err := ParseTPMAuthPolicy(&sAuthPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed reading TPMAuthPolicy: %v", err)
		}
		tkey.authPolicy = authPolicy
	}

	//   parent      INTEGER,
	var parent int
	if !s.ReadASN1Integer(&parent) {
		return nil, errors.New("failed reading parent")
	}
	tkey.Parent = parent

	//   pubkey      OCTET STRING,
	var pubkey cryptobyte.String
	if !s.ReadASN1(&pubkey, asn1.OCTET_STRING) {
		return nil, errors.New("could not parse pubkey")
	}
	tkey.Pubkey = pubkey

	//   privkey     OCTET STRING
	var privkey cryptobyte.String
	if !s.ReadASN1(&privkey, asn1.OCTET_STRING) {
		return nil, errors.New("could not parse privkey")
	}
	tkey.Privkey = privkey

	return &tkey, nil
}

// TPMPolicy ::= SEQUENCE {
//   commandCode   [0] EXPLICIT INTEGER,
//   commandPolicy [1] EXPLICIT OCTET STRING
// }

// TPMAuthPolicy ::= SEQUENCE {
//   name    [0] EXPLICIT UTF8String OPTIONAL,
//   policy  [1] EXPLICIT SEQUENCE OF TPMPolicy
// }

// }
