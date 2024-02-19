package keyfile

import (
	"fmt"
	"testing"
)

func TestHandleMSO(t *testing.T) {
	fmt.Println(IsMSO(0x40000001, TPM_HT_PERMANENT))
}
