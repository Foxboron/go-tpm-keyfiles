package keyfile

var (
	TPM_HT_NV_INDEX       uint32 = 0x01
	TPM_HT_POLICY_SESSION uint32 = 0x03
	TPM_HT_PERMANENT      uint32 = 0x40
	TPM_HT_TRANSIENT      uint32 = 0x80
	TPM_HT_PERSISTENT     uint32 = 0x81
)

func IsMSO(handle, mso uint32) bool {
	return (handle >> 24) == mso
}
