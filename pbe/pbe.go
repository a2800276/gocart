package pbe

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"encoding/asn1"
	"errors"
	"hash"
	//"fmt"
)

type param struct {
	Salt       []byte
	Iterations int
}
type algo struct {
	Algorithm asn1.ObjectIdentifier
	Params    param
}
type pkcs5 struct {
	Algo algo
	Data []byte
}

func PBKDF1(h hash.Hash, password, salt []byte, iterations, dkLen int) ([]byte, error) {
	//http://tools.ietf.org/html/rfc2898#section-5.1
	if dkLen > h.Size() {
		return nil, errors.New("derived key too long")
	}

	h.Write(password)
	h.Write(salt)
	for i := 0; i != iterations-1; i++ {
		crr := h.Sum(nil)
		h.Reset()
		h.Write(crr)
	}
	return h.Sum(nil)[0:dkLen], nil
}
func (p *pkcs5) pbeWithXandDES(x hash.Hash, password []byte) ([]byte, error) {
	// http://tools.ietf.org/html/rfc2898#section-6.1
	dk, err := PBKDF1(x, password, p.Algo.Params.Salt, p.Algo.Params.Iterations, 16)
	if err != nil {
		return nil, err
	}
	k := dk[0:8]
	iv := dk[8:]

	des, err := des.NewCipher(k)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(des, iv)
	bytes := make([]byte, len(p.Data))
	cbc.CryptBlocks(bytes, p.Data)
	pad := bytes[len(bytes)-1:][0]

	return bytes[:len(bytes)-(int)(pad)], nil
	return bytes, nil
}
func (p *pkcs5) pbeWithMD5andDES_CBC(password []byte) ([]byte, error) {
	return p.pbeWithXandDES(md5.New(), password)
}
func (p *pkcs5) pbeWithSHA1andDES_CBC(password []byte) ([]byte, error) {
	return p.pbeWithXandDES(sha1.New(), password)
}

var (
	pbeWithMD2AndDES_CBC  = []int{1, 2, 840, 113549, 1, 5, 1}
	pbeWithMD2AndRC2_CBC  = []int{1, 2, 840, 113549, 1, 5, 4}
	pbeWithMD5AndDES_CBC  = []int{1, 2, 840, 113549, 1, 5, 3}
	pbeWithMD5AndRC2_CBC  = []int{1, 2, 840, 113549, 1, 5, 6}
	pbeWithSHA1AndDES_CBC = []int{1, 2, 840, 113549, 1, 5, 10}
	pbeWithSHA1AndRC2_CBC = []int{1, 2, 840, 113549, 1, 5, 11}
)

func PKCS5(bytes []byte, password []byte) ([]byte, error) {
	var pkcs pkcs5
	rest, err := asn1.Unmarshal(bytes, &pkcs)
	if err != nil {
		return nil, err
	}
	if rest != nil && len(rest) > 0 {
		errors.New("uncertain how to handle: more pkcs stuff left in pkcs5") //TODO
	}
	switch {
	case pkcs.Algo.Algorithm.Equal(pbeWithMD5AndDES_CBC):
		return pkcs.pbeWithMD5andDES_CBC(password)
	case pkcs.Algo.Algorithm.Equal(pbeWithSHA1AndDES_CBC):
		return pkcs.pbeWithSHA1andDES_CBC(password)
	default:
		return nil, errors.New("dont know how to handle") // TODO
	}
	panic("unreachable")
}

// pbeWithMD5AndDES-CBC
// key derivation
// Can't actually find proper information
// about how this is implemeted:
// bouncy castle, pkcs5 1/2, openssl (thks!)
func Openssl(password []byte, salt []byte) []byte {
	// need 64 * 3 bits of key
	key := []byte{}
	// md5 cipher one round per
	hsh := md5.New()
	hsh.Write(password)
	hsh.Write(salt)

	key = append(key, hsh.Sum(nil)...)

	hsh = md5.New()
	hsh.Write(key)
	hsh.Write(password)
	hsh.Write(salt)

	return append(key, hsh.Sum(nil)[0:8]...)
}
