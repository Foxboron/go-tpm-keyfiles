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
		f []byte
	}{
		{
			f: mustOpen("./testdata/rsa-key.tpm"),
		},
		{
			f: mustOpen("./testdata/rsa-tpm-password.tpm"),
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
