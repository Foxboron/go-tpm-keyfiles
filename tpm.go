package keyfile

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// If a permanent handle (MSO 0x40) is specified then the implementation MUST run
	// TPM2_CreatePrimary on the handle using the TCG specified Elliptic Curve
	// template [TCG-Provision] (section 7.5.1 for the Storage and other seeds or
	// 7.4.1 for the endorsement seed) which refers to the TCG EK Credential Profile
	// [TCG-EK-Profile] . Since there are several possible templates, implementations
	// MUST always use the H template (the one with zero size unique fields). The
	// template used MUST be H-2 (EK Credential Profile section B.4.5) for the NIST
	// P-256 curve if rsaParent is absent or the H-1 (EK Credential Profile section
	// B.4.4) RSA template with a key length of 2048 if rsaParent is present and true
	// and use the primary key so generated as the parent.
	ECCSRK_H2_Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
			},
		),
	}
)

// This is a helper to deal with TPM Session encryption.
type TPMSession struct {
	tpm    transport.TPMCloser
	opt    tpm2.AuthOption
	handle tpm2.TPMHandle
}

func NewTPMSession(tpm transport.TPMCloser) *TPMSession {
	var s TPMSession
	s.tpm = tpm
	return &s
}

func (t *TPMSession) SetTPM(tpm transport.TPMCloser) {
	t.tpm = tpm
}

func (t *TPMSession) GetTPM() transport.TPMCloser {
	return t.tpm
}

func (t *TPMSession) SetOpt(opt tpm2.AuthOption) {
	t.opt = opt
}

func (t *TPMSession) SetSalted(handle tpm2.TPMHandle, pub tpm2.TPMTPublic) {
	t.handle = handle
	t.SetOpt(tpm2.Salted(handle, pub))
}

func (t *TPMSession) FlushHandle() {
	FlushHandle(t.tpm, t.handle)
}

func (t *TPMSession) GetHMAC() tpm2.Session {
	// TODO: Do we want a jit encryption or a continous session?
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
		tpm2.AESEncryption(128, tpm2.EncryptInOut),
		t.opt)
}

func (t *TPMSession) GetHMACIn() tpm2.Session {
	// EncryptIn and EncryptInOut are internal to go-tpm so.. this is the solution
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
		tpm2.AESEncryption(128, tpm2.EncryptIn),
		t.opt)
}

func LoadKeyWithParent(session *TPMSession, parent tpm2.AuthHandle, key *TPMKey) (*tpm2.AuthHandle, error) {
	loadBlobCmd := tpm2.Load{
		ParentHandle: parent,
		InPrivate:    key.Privkey,
		InPublic:     key.Pubkey,
	}
	loadBlobRsp, err := loadBlobCmd.Execute(session.GetTPM())
	if err != nil {
		return nil, fmt.Errorf("failed getting handle: %v", err)
	}

	// Return a AuthHandle with a nil PasswordAuth
	return &tpm2.AuthHandle{
		Handle: loadBlobRsp.ObjectHandle,
		Name:   loadBlobRsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, nil
}

func LoadKey(tpm transport.TPMCloser, key *TPMKey, ownerauth []byte) (*tpm2.AuthHandle, error) {
	var sess TPMSession

	sess.SetTPM(tpm)

	if !key.Keytype.Equal(OIDLoadableKey) {
		return nil, fmt.Errorf("not a loadable key")
	}

	parenthandle, err := GetParentHandle(&sess, key.Parent, ownerauth)
	if err != nil {
		return nil, err
	}
	defer sess.FlushHandle()

	return LoadKeyWithParent(&sess, *parenthandle, key)
}

// Creates a Storage Key, or return the loaded storage key
func CreateSRK(sess *TPMSession, hier tpm2.TPMHandle, ownerAuth []byte) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	public := tpm2.New2B(ECCSRK_H2_Template)

	srk := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: hier,
			Auth:   tpm2.PasswordAuth(ownerAuth),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
		InPublic: public,
	}

	var rsp *tpm2.CreatePrimaryResponse
	rsp, err := srk.Execute(sess.GetTPM())
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating primary key: %v", err)
	}

	srkPublic, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting srk public content: %v", err)
	}

	return &tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, srkPublic, nil
}

func createECCKey(ecc tpm2.TPMECCCurve, sha tpm2.TPMAlgID) tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic] {
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: sha,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: ecc,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			},
		),
	})
}

func createRSAKey(bits tpm2.TPMKeyBits, sha tpm2.TPMAlgID) tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic] {
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: sha,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				KeyBits: bits,
			},
		),
	})
}

// from crypto/ecdsa
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

// from crypto/ecdsa
func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

func newECCSigScheme(digest tpm2.TPMAlgID) tpm2.TPMTSigScheme {
	return tpm2.TPMTSigScheme{
		Scheme: tpm2.TPMAlgECDSA,
		Details: tpm2.NewTPMUSigScheme(
			tpm2.TPMAlgECDSA,
			&tpm2.TPMSSchemeHash{
				HashAlg: digest,
			},
		),
	}
}

func newRSASigScheme(digest tpm2.TPMAlgID) tpm2.TPMTSigScheme {
	return tpm2.TPMTSigScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUSigScheme(
			tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSchemeHash{
				HashAlg: digest,
			},
		),
	}
}

func Sign(sess *TPMSession, key *TPMKey, ownerauth, auth, digest []byte, digestalgo tpm2.TPMAlgID) (*tpm2.TPMTSignature, error) {
	var digestlength int

	switch digestalgo {
	case tpm2.TPMAlgSHA256:
		digestlength = 32
	case tpm2.TPMAlgSHA384:
		digestlength = 48
	case tpm2.TPMAlgSHA512:
		digestlength = 64
	default:
		return nil, fmt.Errorf("%v is not a supported hashing algorithm", digestalgo)
	}

	if len(digest) != digestlength {
		return nil, fmt.Errorf("incorrect checksum length. expected %v got %v", digestlength, len(digest))
	}

	srkHandle, srkPublic, err := CreateSRK(sess, tpm2.TPMRHOwner, ownerauth)
	if err != nil {
		return nil, fmt.Errorf("failed creating SRK: %v", err)
	}
	sess.SetSalted(srkHandle.Handle, *srkPublic)
	defer FlushHandle(sess.GetTPM(), srkHandle)

	handle, err := LoadKeyWithParent(sess, *srkHandle, key)
	if err != nil {
		return nil, err
	}
	defer FlushHandle(sess.GetTPM(), handle)

	if len(auth) != 0 {
		handle.Auth = tpm2.PasswordAuth(auth)
	}

	var sigscheme tpm2.TPMTSigScheme
	switch key.KeyAlgo() {
	case tpm2.TPMAlgECC:
		sigscheme = newECCSigScheme(digestalgo)
	case tpm2.TPMAlgRSA:
		sigscheme = newRSASigScheme(digestalgo)
	}

	sign := tpm2.Sign{
		KeyHandle: *handle,
		Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme:  sigscheme,
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}

	rspSign, err := sign.Execute(sess.GetTPM(), sess.GetHMACIn())
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return &rspSign.Signature, nil
}

func SignASN1(sess *TPMSession, key *TPMKey, ownerauth, auth, digest []byte, digestalgo tpm2.TPMAlgID) ([]byte, error) {
	rsp, err := Sign(sess, key, ownerauth, auth, digest, digestalgo)
	if err != nil {
		return nil, err
	}
	switch key.KeyAlgo() {
	case tpm2.TPMAlgECC:
		eccsig, err := rsp.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("failed getting signature: %v", err)
		}
		return encodeSignature(eccsig.SignatureR.Buffer, eccsig.SignatureS.Buffer)
	case tpm2.TPMAlgRSA:
		rsassa, err := rsp.Signature.RSASSA()
		if err != nil {
			return nil, fmt.Errorf("failed getting rsassa signature")
		}
		return rsassa.Sig.Buffer, nil
	}
	return nil, fmt.Errorf("failed returning signature")
}

// shadow the unexported interface from go-tpm
type handle interface {
	HandleValue() uint32
	KnownName() *tpm2.TPM2BName
}

// Helper to flush handles
func FlushHandle(tpm transport.TPM, h handle) {
	//TODO: We should probably handle the error here
	flushSrk := tpm2.FlushContext{FlushHandle: h}
	flushSrk.Execute(tpm)
}

func SupportedECCAlgorithms(tpm transport.TPMCloser) []int {
	var getCapRsp *tpm2.GetCapabilityResponse
	var supportedBitsizes []int

	eccCapCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapECCCurves,
		PropertyCount: 100,
	}
	getCapRsp, err := eccCapCmd.Execute(tpm)
	if err != nil {
		return []int{}
	}
	curves, err := getCapRsp.CapabilityData.Data.ECCCurves()
	if err != nil {
		return []int{}
	}
	for _, curve := range curves.ECCCurves {
		c, err := curve.Curve()
		// if we fail here we are dealing with an unsupported curve
		if err != nil {
			continue
		}
		supportedBitsizes = append(supportedBitsizes, c.Params().BitSize)
	}
	return supportedBitsizes
}

func createKeyWithHandle(sess *TPMSession, parent tpm2.AuthHandle, keytype tpm2.TPMAlgID, bits int, ownerAuth []byte, auth []byte) (tpm2.TPM2BPublic, tpm2.TPM2BPrivate, error) {
	rsaBits := []int{2048}
	ecdsaBits := []int{256, 384, 521}

	supportedECCBitsizes := SupportedECCAlgorithms(sess.GetTPM())

	switch keytype {
	case tpm2.TPMAlgECC:
		if bits == 0 {
			bits = ecdsaBits[0]
		}
		if !slices.Contains(ecdsaBits, bits) {
			return tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, errors.New("invalid ecdsa key length: valid length are 256, 384 or 512 bits")
		}
		if !slices.Contains(supportedECCBitsizes, bits) {
			return tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, fmt.Errorf("invalid ecdsa key length: TPM does not support %v bits", bits)
		}
	case tpm2.TPMAlgRSA:
		if bits == 0 {
			bits = rsaBits[0]
		}
		if !slices.Contains(rsaBits, bits) {
			return tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, errors.New("invalid rsa key length: only 2048 is supported")
		}
	default:
		return tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, fmt.Errorf("unsupported key type")
	}

	var keyPublic tpm2.TPM2BPublic
	switch {
	case keytype == tpm2.TPMAlgECC && bits == 256:
		keyPublic = createECCKey(tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256)
	case keytype == tpm2.TPMAlgECC && bits == 384:
		keyPublic = createECCKey(tpm2.TPMECCNistP384, tpm2.TPMAlgSHA256)
	case keytype == tpm2.TPMAlgECC && bits == 521:
		keyPublic = createECCKey(tpm2.TPMECCNistP521, tpm2.TPMAlgSHA256)
	case keytype == tpm2.TPMAlgRSA:
		keyPublic = createRSAKey(2048, tpm2.TPMAlgSHA256)
	}

	// Template for en ECC key for signing
	createKey := tpm2.Create{
		ParentHandle: parent,
		InPublic:     keyPublic,
	}

	if !bytes.Equal(auth, []byte("")) {
		createKey.InSensitive = tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: auth,
				},
			},
		}
	}

	createRsp, err := createKey.Execute(sess.GetTPM(), sess.GetHMAC())
	if err != nil {
		return tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, fmt.Errorf("failed creating TPM key: %v", err)
	}

	return createRsp.OutPublic, createRsp.OutPrivate, nil
}

// TODO: Private until I'm confident of the API
func createKey(sess *TPMSession, keytype tpm2.TPMAlgID, bits int, ownerAuth []byte, auth []byte) (tpm2.TPM2BPublic, tpm2.TPM2BPrivate, error) {
	srkHandle, pub, err := CreateSRK(sess, tpm2.TPMRHOwner, ownerAuth)
	if err != nil {
		return tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, err
	}
	sess.SetSalted(srkHandle.Handle, *pub)
	defer FlushHandle(sess.GetTPM(), srkHandle)
	return createKeyWithHandle(sess, *srkHandle, keytype, bits, ownerAuth, auth)
}

func ReadPublic(tpm transport.TPMCloser, handle tpm2.TPMHandle) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	rsp, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm)
	if err != nil {
		return nil, nil, err
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}
	return &tpm2.AuthHandle{
		Handle: handle,
		Name:   rsp.QualifiedName,
	}, pub, nil
}

// This looks at the passed parent defined in a TPMKey and gives back the
// appropriate handle to load our TPM key under.
// With a PERMANENT handle it will load an transient SRK under the parent heier,
// and give back the handle.
// With a TRANSIENT handle it will load a transient SRK under the Owner hier,
// and hand back the handle.
// With a PERSISTENT handle it will try to read the public portion of the key.
//
// This function will also set the appropriate bound HMAC session to the
// returned keys.
func GetParentHandle(sess *TPMSession, parent tpm2.TPMHandle, ownerauth []byte) (*tpm2.AuthHandle, error) {
	var parenthandle tpm2.AuthHandle

	if IsMSO(parent, TPM_HT_PERMANENT) {
		srkHandle, pub, err := CreateSRK(sess, parent, ownerauth)
		if err != nil {
			return nil, err
		}
		sess.SetSalted(srkHandle.Handle, *pub)
		parenthandle = *srkHandle
	} else if IsMSO(parent, TPM_HT_TRANSIENT) {
		// Parent should never be transient, but we might have keys that use the
		// wrong handle lets try to load this under the owner hier
		srkHandle, pub, err := CreateSRK(sess, tpm2.TPMRHOwner, ownerauth)
		if err != nil {
			return nil, err
		}
		sess.SetSalted(srkHandle.Handle, *pub)
		parenthandle = *srkHandle
	} else if IsMSO(parent, TPM_HT_PERSISTENT) {
		handle, pub, err := ReadPublic(sess.GetTPM(), parent)
		if err != nil {
			return nil, err
		}
		parenthandle = *handle

		// TODO: Unclear to me if we just load the EK and use that, instead of the key.
		sess.SetSalted(parent, *pub)
	}
	return &parenthandle, nil
}
