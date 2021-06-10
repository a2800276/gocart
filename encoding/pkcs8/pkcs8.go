package encoding

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)
import goca_pem "github.com/a2800276/gocart/encoding/pem"

func t() {
	fmt.Printf("%s\n", time.Now())
}

func LoadPKCS8(fn string) (*rsa.PrivateKey, error) {
	something, err := goca_pem.LoadPEMFile(fn, nil)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := something.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an rsa private key")
	}

	return rsaKey, nil
}

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn.
//
// stolen wholesale from: src/pkg/crypto/x509/pkcs8.go ..
//  build for dsa and ec keys ...
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

var oidRSA = []int{1, 2, 840, 113549, 1, 1, 1}

// .. till here

func WritePKtoPKCS8PEMFile(fn string, pk *rsa.PrivateKey) error {

	file, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	return WritePKtoPKCS8PEM(file, pk)
}

func WritePKtoPKCS8PEM(writer io.Writer, pk *rsa.PrivateKey) error {
	pkcs1 := x509.MarshalPKCS1PrivateKey(pk)
	algo := pkix.AlgorithmIdentifier{Algorithm: oidRSA}
	pkcs8struct := pkcs8{0, algo, pkcs1}
	bytes, err := asn1.Marshal(pkcs8struct)
	if err != nil {
		return err
	}
	block := &pem.Block{"PRIVATE KEY", nil, bytes}
	err = pem.Encode(writer, block)
	if err != nil {
		return err
	}
	return nil
}
