package keyfile

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestHandleMSO(t *testing.T) {
	for _, c := range []struct {
		h  tpm2.TPMHandle
		m  uint32
		ok bool
	}{
		{
			0x40000001,
			TPM_HT_PERMANENT,
			true,
		},
		{
			0x41000001,
			TPM_HT_PERMANENT,
			false,
		},
	} {

		if ok := IsMSO(c.h, c.m); ok != c.ok {
			t.Fatalf("mso doesn't match. expected %v got %v", c.ok, ok)
		}
	}
}
