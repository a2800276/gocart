// This is more or less a copy of the pkcs1 loading
// from the go runtime.

// unfortunately, the runtime version precalculated
// CRT key components when loading keys. When you just need to
// load the keys and not actually use them, this is a
// consideral overhead, so this package contains the
// loading routines with the optimization disabled.

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

var oidRSA = []int{1, 2, 840, 113549, 1, 1, 1}

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

// ParsePKCS8PrivateKey parses an unencrypted, PKCS#8 private key. See
// http://www.rsa.com/rsalabs/node.asp?id=2130
func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	return parsePKCS8PrivateKey(der, true)
}
func FastParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	return parsePKCS8PrivateKey(der, false)
}
func parsePKCS8PrivateKey(der []byte, precompute bool) (key interface{}, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	switch {
	case privKey.Algo.Algorithm.Equal(oidRSA):
		if precompute {
			key, err = ParsePKCS1PrivateKey(privKey.PrivateKey)
		} else {
			key, err = FastParsePKCS1PrivateKey(privKey.PrivateKey)
		}
		if err != nil {
			return nil, errors.New("crypto/x509: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil
	default:
		return nil, fmt.Errorf("crypto/x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}

	panic("unreachable")
}
