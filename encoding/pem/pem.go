package pem

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"fmt"
)

import "github.com/a2800276/gocart/pbe"
import "github.com/a2800276/gocart/csr"
import myx509 "github.com/a2800276/gocart/x509"

const pem_hdr_proc_type = "Proc-Type"
const pem_hdr_dek_info = "DEK-Info"

const pem_hdr_3des_cdc = "DES-EDE3-CBC"

//const PEM_CERTIFICATE = "CERTIFICATE"
//const PEM_PRIVATE_KEY = "PRIVATE KEY"
//const PEM_RSA_PRIVATE_KEY = "RSA PRIVATE KEY"
//const PEM_CERTIFICATE_REQ = "CERTIFICATE REQUEST"
//const PEM_ENC_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY"

type PemType string

const (
	// orig from: (<openssl>/crypto/pem/pem.h l.114ff openssl 1.0.1c)
	PEM_X509_OLD        PemType = "X509 CERTIFICATE"
	PEM_X509            PemType = "CERTIFICATE"
	PEM_CERTIFICATE     PemType = PEM_X509
	PEM_X509_PAIR       PemType = "CERTIFICATE PAIR"
	PEM_X509_TRUSTED    PemType = "TRUSTED CERTIFICATE"
	PEM_X509_REQ_OLD    PemType = "NEW CERTIFICATE REQUEST"
	PEM_X509_REQ        PemType = "CERTIFICATE REQUEST"
	PEM_CSR             PemType = PEM_X509_REQ
	PEM_X509_CRL        PemType = "X509 CRL"
	PEM_EVP_PKEY        PemType = "ANY PRIVATE KEY"
	PEM_PUBLIC          PemType = "PUBLIC KEY"
	PEM_RSA             PemType = "RSA PRIVATE KEY"
	PEM_RSA_PUBLIC      PemType = "RSA PUBLIC KEY"
	PEM_DSA             PemType = "DSA PRIVATE KEY"
	PEM_DSA_PUBLIC      PemType = "DSA PUBLIC KEY"
	PEM_PKCS7           PemType = "PKCS7"
	PEM_PKCS7_SIGNED    PemType = "PKCS #7 SIGNED DATA"
	PEM_PKCS8           PemType = "ENCRYPTED PRIVATE KEY"
	PEM_ENC_PRIVATE_KEY PemType = PEM_PKCS8
	PEM_PKCS8INF        PemType = "PRIVATE KEY"
	PEM_PRIVATE_KEY     PemType = PEM_PKCS8INF
	PEM_DHPARAMS        PemType = "DH PARAMETERS"
	PEM_SSL_SESSION     PemType = "SSL SESSION PARAMETERS"
	PEM_DSAPARAMS       PemType = "DSA PARAMETERS"
	PEM_ECDSA_PUBLIC    PemType = "ECDSA PUBLIC KEY"
	PEM_ECPARAMETERS    PemType = "EC PARAMETERS"
	PEM_ECPRIVATEKEY    PemType = "EC PRIVATE KEY"
	PEM_PARAMETERS      PemType = "PARAMETERS"
	PEM_CMS             PemType = "CMS"
)

func LoadPEMFile(fn string, credentials interface{}) (interface{}, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return LoadPEM(f, credentials)
}

func LoadPEM(r io.Reader, credentials interface{}) (interface{}, error) {
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("no pem data found")
	}
	if rest != nil && len(rest) != 0 {
		return nil, errors.New("superfluous data in pem...")
	}
	// header decode
	// ugh. handle decode. RFC 1421:
	// 4.6.1.1
	// only interested in Proc-Type: 4, ENCRYPTED
	procType := block.Headers[pem_hdr_proc_type]
	if len(procType) != 0 {
		bytes, err = decipher_pem(block, credentials)
		if err != nil {
			return nil, err
		}
	} else {
		bytes = block.Bytes
	}
	//fmt.Printf("<- %s\n", base64.StdEncoding.EncodeToString(bytes))
	//fmt.Printf("<- %x\n", bytes)
	switch block.Type {
	case string(PEM_CERTIFICATE):
		cs, err := x509.ParseCertificates(bytes)
		if err != nil {
			return nil, err
		}
		if len(cs) != 1 {
			return nil, errors.New("incorrect number of certificates in PEM")
		}
		return cs[0], nil
	case string(PEM_RSA):
		return myx509.FastParsePKCS1PrivateKey(bytes)
	case string(PEM_PRIVATE_KEY):
		// private keys also contain an oid specifying what they are.
		return myx509.FastParsePKCS8PrivateKey(bytes)
	case string(PEM_ENC_PRIVATE_KEY):
		// enc can either be PKCS5 or handle by PEM as stated
		// the header. This is PKCS5, enc paramas are in ASN.1
		pswd, ok := credentials.([]byte)
		if !ok {
			if pswd2, ok := credentials.(string); !ok {
				return nil, errors.New("no password")
			} else {
				pswd = ([]byte)(pswd2)
			}
		}
		if bytes, err := pbe.PKCS5(bytes, pswd); err != nil {
			return nil, err
		} else {
			return myx509.FastParsePKCS8PrivateKey(bytes)
		}
	case string(PEM_CSR):
		return csr.DecodePKCS10(bytes)
	default:
		return nil, errors.New(fmt.Sprintf("don't know how to handle: %s", block.Type))
	}
	// type
	fmt.Printf("%s\n", block.Headers)
	return nil, nil
}

func decipher_pem(block *pem.Block, cred interface{}) ([]byte, error) {
	// this is openssl (1.0.1)'s default:
	//DEK-Info: DES-EDE3-CBC,5C9D3F709BB634B0
	// the second bit is the IV and salt to the pbe algo.
	// currently this is all we support.

	dek_info_hdr := block.Headers[pem_hdr_dek_info]
	if len(dek_info_hdr) == 0 {
		return nil, errors.New("No DEK-Info header in ecrypted PEM")
	}

	dek_info := strings.Split(dek_info_hdr, ",")
	for i, v := range dek_info {
		dek_info[i] = strings.TrimSpace(v)
	}

	switch dek_info[0] {
	case pem_hdr_3des_cdc:
		if len(dek_info) != 2 {
			return nil, errors.New("unexpected parameters for 3DES")
		}
		return decipher_3des_cdc(block.Bytes, dek_info[1], cred)
	default:
		return nil, fmt.Errorf("unexpected DEK Info: %s", dek_info_hdr)
	}
	panic("unreachable")
	return nil, nil
}

func decipher_3des_cdc(bytes []byte, ivs string, credentials interface{}) ([]byte, error) {
	// good lord, openssl is a nightmare...
	// encryption is with own pbe and padding is pkcs7/rfc5652, i.e. everything is padded with
	// XX * 0xXX to block bondaries, e.g.: missing 4 bytes to block boundary? pad with 04040404

	iv, err := hex.DecodeString(ivs)
	if err != nil {
		return nil, err
	}
	pswd, ok := credentials.([]byte)
	if !ok {
		return nil, errors.New("no key for decryption")
	}
	key := pbe.Openssl(pswd, iv)
	des, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(des, iv)
	cbc.CryptBlocks(bytes, bytes)

	pad := bytes[len(bytes)-1:][0]            // value of last byte. padding val == number of bytes ...
	return bytes[:len(bytes)-(int)(pad)], nil // to strip from end of value
}

func LoadCertificateFromPEM(reader io.Reader) (*x509.Certificate, error) {
	something, err := LoadPEM(reader, nil)
	if err != nil {
		return nil, err
	}
	if cert, ok := something.(*x509.Certificate); !ok {
		return nil, errors.New("not an x509 certificate")
	} else {
		return cert, nil
	}
	panic("unreachable")
	return nil, nil
}

func StorePEM(fn string, type_name string, bytes []byte) error {
	file, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Printf("%s\n", err)
		return err
	}
	defer file.Close()

	return WritePEM(file, type_name, bytes)
}

func WritePEM(writer io.Writer, type_name string, bytes []byte) error {
	block := &pem.Block{type_name, nil, bytes}
	if err := pem.Encode(writer, block); err != nil {
		return err
	}
	return nil
}

func DecodeCSRPEM(reader io.Reader) (*csr.CSR, error) {
	something, err := LoadPEM(reader, nil)
	if err != nil {
		return nil, err
	}
	if csr, ok := something.(*csr.CSR); !ok {
		return nil, errors.New("Not a CSR")
	} else {
		return csr, nil
	}
	panic("unreachable")
}
