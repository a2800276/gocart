package pem

import (
	"crypto/rsa"
	"testing"
)

const enc_keys = "../../test_cert/123.keye"

var test_key = ([]byte)("testtest")

func TestLoadPemEnc(t *testing.T) {
	k, err := LoadPEMFile(enc_keys, test_key)
	if err != nil {
		t.Fatalf("couldn't load: %s err: %s", enc_keys, err)
	}
	keys, ok := k.(*rsa.PrivateKey)
	if !ok {
		t.Error("didn't load rsa pub keys", keys)
	}
}
