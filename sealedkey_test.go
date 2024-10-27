package keyfile

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestSealedData(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("message")
	}
	defer tpm.Close()

	msg := []byte("message")

	k, err := NewSealedData(tpm, msg, []byte(nil))
	if err != nil {
		t.Fatalf("message")
	}

	data, err := UnsealData(tpm, k, []byte(nil))
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(data, msg) {
		t.Fatalf("unsealed data is not the same as data")
	}
}
