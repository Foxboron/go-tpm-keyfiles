package pcrlock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TODO: Seperate this out into it's own library at some point

const pcrlockPolicy = "/var/lib/systemd/pcrlock.json"

type PCRValue struct {
	PCR    uint     `json:"pcr"`
	Values []string `json:"values"`
}

func (p *PCRValue) GetPolicyWithCalculator(calc *tpm2.PolicyCalculator) (*tpm2.PolicyCalculator, error) {
	digests := []tpm2.TPM2BDigest{}

	if len(p.Values) < 2 {
		return nil, fmt.Errorf("pcrlock: only policies with branches are supported")
	}

	for _, value := range p.Values {
		pol := calc.Clone()
		bytes, err := hex.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("failed to decode string")
		}
		h := sha256.Sum256(bytes)
		err = tpm2.PolicyPCR{
			PcrDigest: tpm2.TPM2BDigest{Buffer: h[:]},
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(p.PCR),
					},
				},
			},
		}.Update(pol)
		if err != nil {
			return nil, err
		}

		digests = append(digests, tpm2.TPM2BDigest{
			Buffer: pol.Hash().Digest,
		})
		// fmt.Printf("PolicyPCR calculated digest: %x\n", pol.Hash().Digest)
	}
	err := tpm2.PolicyOr{
		PHashList: tpm2.TPMLDigest{
			Digests: digests,
		},
	}.Update(calc)
	if err != nil {
		return nil, fmt.Errorf("failed updating PolicyOR calculator")
	}

	// fmt.Printf("PolicyOR calculated digest: %x\n", calc.Hash().Digest)
	return calc, nil
}

func (p *PCRValue) GetPolicy() (*tpm2.PolicyCalculator, error) {
	pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, fmt.Errorf("failed getting calculator")
	}
	return p.GetPolicyWithCalculator(pol)
}

func (p *PCRValue) GetPolicySession(rwc transport.TPMCloser, sess tpm2.Session, calc *tpm2.PolicyCalculator) (*tpm2.PolicyCalculator, error) {
	digests := []tpm2.TPM2BDigest{}

	if len(p.Values) < 2 {
		return nil, fmt.Errorf("pcrlock: only policies with branches are supported")
	}

	// We run PolicyPCR on our current PCR
	_, err := tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest:     tpm2.TPM2BDigest{},
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(p.PCR),
				},
			},
		},
	}.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed executing PolicyPCR with session")
	}

	for _, value := range p.Values {
		// We clone the "super" policy session
		pol := calc.Clone()
		bytes, err := hex.DecodeString(value)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(bytes)
		err = tpm2.PolicyPCR{
			PcrDigest: tpm2.TPM2BDigest{Buffer: h[:]},
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(p.PCR),
					},
				},
			},
		}.Update(pol)
		if err != nil {
			return nil, nil
		}

		digests = append(digests, tpm2.TPM2BDigest{
			Buffer: pol.Hash().Digest,
		})
		// fmt.Printf("PolicyPCR calculated digest: %x\n", pol.Hash().Digest)
	}
	orPolicy := tpm2.PolicyOr{
		PHashList: tpm2.TPMLDigest{
			Digests: digests,
		},
	}

	if err := orPolicy.Update(calc); err != nil {
		return nil, fmt.Errorf("failed updating calculator")
	}

	orPolicy.PolicySession = sess.Handle()
	if _, err := orPolicy.Execute(rwc); err != nil {
		return nil, fmt.Errorf("PolicyOR did not match any of the current states")
	}

	// fmt.Printf("PolicyOR calculated digest: %x\n", calc.Hash().Digest)
	return calc, nil
}

type PCRLock struct {
	PCRBank    string      `json:"pcrBank"`
	PCRValues  []*PCRValue `json:"pcrValues"`
	NVIndex    int         `json:"nvIndex"`
	NVHandle   []byte      `json:"nvHandle"`
	NVPublic   []byte      `json:"nvPublic"`
	SRKHandle  []byte      `json:"srkHandle"`
	PINPublic  []byte      `json:"pinPublic"`
	PINPrivate []byte      `json:"pinPrivate"`
}

func (p *PCRLock) GetPolicySession(rwc transport.TPMCloser, s tpm2.Session) (*tpm2.PolicyCalculator, []byte, error) {
	// We assume a null policydigest at this point for the offline branch calculcation
	// I don't know how we go from GetPolicyDigest into a PolicyCalculcator
	// FIXME: this will be an issue at some point
	pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, nil, err
	}

	for _, pcr := range p.PCRValues {
		superPol := pol.Clone()
		pp, err := pcr.GetPolicySession(rwc, s, superPol)
		if err != nil {
			return nil, nil, err
		}
		pol = pp
	}
	return nil, nil, nil
}

func (p *PCRLock) Policy() (*tpm2.PolicyCalculator, []byte, error) {
	pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		panic("this should not happen")
	}

	for _, pcr := range p.PCRValues {
		superPol := pol.Clone()
		pp, err := pcr.GetPolicyWithCalculator(superPol)
		if err != nil {
			return nil, nil, err
		}
		pol = pp
	}
	return pol, pol.Hash().Digest, nil
}

func ReadPolicy(f string) (*PCRLock, error) {
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return ParsePolicy(b)
}

func ParsePolicy(b []byte) (*PCRLock, error) {
	var pcrlock PCRLock
	if err := json.Unmarshal(b, &pcrlock); err != nil {
		return nil, err
	}
	return &pcrlock, nil
}
