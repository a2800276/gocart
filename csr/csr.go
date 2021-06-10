package csr

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

type SubjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type CertificationRequestInfo struct {
	Raw                  asn1.RawContent
	Version              int
	Subject              pkix.RDNSequence
	SubjectPublicKeyInfo SubjectPublicKeyInfo
}

type CSR struct {
	Raw                      asn1.RawContent
	CertificationRequestInfo CertificationRequestInfo
	SignatureAlgorithm       pkix.AlgorithmIdentifier
	SignatureValue           asn1.BitString
}

func DecodePKCS10(bytes []byte) (*CSR, error) {
	var csr CSR
	rest, err := asn1.Unmarshal(bytes, &csr)
	if err != nil {
		return nil, err
	}
	if rest != nil && len(rest) > 0 {
		// TODO sanity
	}
	return &csr, nil
}
