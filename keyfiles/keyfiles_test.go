package keyfiles

import (
	"fmt"
	"log"
	"os"
	"testing"
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
			_, err := Parse(tt.f)
			if err != nil {
				t.Fatalf("failed parsing: %v", err)
			}
		})
	}
}
