package pbe_test

import "crypto/rsa"
import "crypto/md5"
import "crypto/sha1"

//import "encoding/base64"
import "testing"
import "bytes"
import "fmt"

import "github.com/a2800276/gocart/encoding/pem"
import "github.com/a2800276/gocart/pbe"

const enc_key = "../test_cert/234.pkcs8e"
const pswd = "testtest"

func TestLoad(t *testing.T) {
	something, err := pem.LoadPEMFile(enc_key, pswd)
	if err != nil {
		t.Error(err)
	}
	//b, _ := something.([]byte)

	fmt.Printf("%x\n", something)
	if _, ok := something.(*rsa.PrivateKey); !ok {
		t.Error("not a private key")
	}
}

var (
	md5dk  = []byte{0x84, 0x75, 0xc6, 0xa8, 0x53, 0x1a, 0x5d, 0x27, 0xe3, 0x86, 0xcd, 0x49, 0x64, 0x57, 0x81, 0x2c}
	sha1dk = []byte{0x4a, 0x8f, 0xd4, 0x8e, 0x42, 0x6e, 0xd0, 0x81, 0xb5, 0x35, 0xbe, 0x57, 0x69, 0x89, 0x2f, 0xa3, 0x96, 0x29, 0x3e, 0xfb}
)

func TestPBKDF1(t *testing.T) {
	b, err := pbe.PBKDF1(md5.New(), ([]byte)("password"), ([]byte)("salt"), 1000, 16)
	if err != nil {
		t.Error(err)
	}
	if 0 != bytes.Compare(b, md5dk) {
		t.Error("Key derivation incorrect (MD5)")
	}

	b, err = pbe.PBKDF1(sha1.New(), ([]byte)("password"), ([]byte)("salt"), 1000, 20)
	if err != nil {
		t.Error(err)
	}
	if 0 != bytes.Compare(b, sha1dk) {
		t.Error("Key derivation incorrect (SHA1)")
	}
}
