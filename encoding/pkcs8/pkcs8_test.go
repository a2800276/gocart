package encoding

import "testing"

//import "fmt"
import "crypto/rsa"
import "os"

//import "math/big"

const (
	pkcs8file = "../../test_cert/pkcs8test.pkcs8"
	pkcs8iden = "../../test_cert/pkcs8iden.pkcs8"
)

func TestPKCS8Load(t *testing.T) {
	_, err := LoadPKCS8(pkcs8file)
	if err != nil {
		t.Error("error loading pkcs8", err)
	}
}

func TestPKCS8Write(t *testing.T) {
	pk, err := LoadPKCS8(pkcs8file)
	if err != nil {
		t.Error("error loading pkcs8", err)
	}

	err = WritePKtoPKCS8PEMFile(pkcs8iden, pk)
	if err != nil {
		t.Error("error (re)saving pkcs8", err)
	}

	pk2, err := LoadPKCS8(pkcs8iden)
	if err != nil {
		t.Error("error (re)loading pkcs8", err)
	}
	if !equals(pk, pk2) {
		t.Error("key round trip (load and save) unsuccessful")
	}
	os.Remove(pkcs8iden)
}

func equals(pk, pk2 *rsa.PrivateKey) bool {
	if pk.D.Cmp(pk2.D) != 0 {
		return false
	}
	primes1 := pk.Primes
	primes2 := pk2.Primes
	for i, _ := range primes1 {
		if primes1[i].Cmp(primes2[i]) != 0 {
			return false
		}
	}
	return true
}
