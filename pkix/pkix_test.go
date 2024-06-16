package pkix

import "testing"

var key = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0BHjtdoUY4xhfPTfpkyNrp34GLpF
bacHq+W6Jfx5HZ5pVqpQWoTXf/qF+Y+kr4T3t3dlTYkNTx5DcbdZY3mKpw==
-----END PUBLIC KEY-----`)

func TestToTPMPublic(t *testing.T) {
	ToTPMPublic(key)
}
