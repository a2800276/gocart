package x509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"time"
)

// This file contains a number of types that are meant to facilitate
// working with x509, etc. type data in the context of the web. The GO
// Runtime types (in crypto.x509) are more useful in the context of
// working with ASN.1 representations of the data. The types in the
// package more or less just flatten the original types from the RT and
// provide facilities to convert them to JSON and the crypto/x509 types.

// Data required to generate a Certificate.
// Currently this is restricted to the possibilities offered by the Go
// RT, i.e. restrictions on the available extensions and only SHA1
// signed RSA keys.
//
// TODO: check the above statement, code is originally from go 0.000001
// so things might have improved.

type CertificateData struct {
	SerialNumber Hex       `json:"serialNumber"` // optional generated from PubKey if not present
	Subject      Subject   `json:"subject"`
	Issuer       Subject   `json:"issuer"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	KeyUsage     KeyUsage  `json:"keyUsage"`

	BasicConstraintsValid bool `json:"basicConstraintsValid"` // optional
	IsCA                  bool `json:"isCA"`                  // optional depends on BasicConstraintsValid
	MaxPathLen            int  `json:"maxPathLen"`            // ditto

	SubjectKeyId   Hex `json:"subjectKeyId"`   // optional
	AuthorityKeyId Hex `json:"authorityKeyId"` // optional

	DNSNames                    []string `json:"DNSNames"`                    // optional "subjectAltNames"
	PermittedDNSDomainsCritical bool     `json:"permittedDNSDomainsCritical"` // optional only used if PermittedDNSDomains
	PermittedDNSDomains         []string `json:"permittedDNSDomains"`         // optional

	// the following are not used when creating the
	// certificate, ony for json encoding.
	PublicKey PublicKey `json:"publicKey"`
	Signature Signature `json:"signature"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	Signature Hex    `json:"signature"`
}
type PublicKey struct {
	Algorithm string `json:"algorithm"`
	Modulus   Hex    `json:"modulus"`
	Exponent  int    `json:"exponent"`
}

// Flattened x509.KeyUsage, this is a bitmap in the original.
type KeyUsage struct {
	DigitalSignature  bool `json:"digitalSignature"`
	ContentCommitment bool `json:"contentCommitment"`
	KeyEncipherment   bool `json:"keyEncipherment"`
	DataEncipherment  bool `json:"dataEncipherment"`
	KeyAgreement      bool `json:"keyAgreement"`
	CertSign          bool `json:"certSign"`
	CRLSign           bool `json:"crlSign"`
	EncipherOnly      bool `json:"encipherOnly"`
	DecipherOnly      bool `json:"decipherOnly"`
}

func ToKeyUsage(usage x509.KeyUsage) (ku KeyUsage) {
	ku.DigitalSignature = (usage & x509.KeyUsageDigitalSignature) != 0
	ku.ContentCommitment = (usage & x509.KeyUsageContentCommitment) != 0
	ku.KeyEncipherment = (usage & x509.KeyUsageKeyEncipherment) != 0
	ku.DataEncipherment = (usage & x509.KeyUsageDataEncipherment) != 0
	ku.KeyAgreement = (usage & x509.KeyUsageKeyAgreement) != 0
	ku.CertSign = (usage & x509.KeyUsageCertSign) != 0
	ku.CRLSign = (usage & x509.KeyUsageCRLSign) != 0
	ku.EncipherOnly = (usage & x509.KeyUsageEncipherOnly) != 0
	ku.DecipherOnly = (usage & x509.KeyUsageDecipherOnly) != 0
	return
}

func (ku KeyUsage) toX509KeyUsage() x509.KeyUsage {
	var x509ku x509.KeyUsage = 0

	if ku.DigitalSignature {
		x509ku |= x509.KeyUsageDigitalSignature
	}
	if ku.ContentCommitment {
		x509ku |= x509.KeyUsageContentCommitment
	}
	if ku.KeyEncipherment {
		x509ku |= x509.KeyUsageKeyEncipherment
	}
	if ku.DataEncipherment {
		x509ku |= x509.KeyUsageDataEncipherment
	}
	if ku.KeyAgreement {
		x509ku |= x509.KeyUsageKeyAgreement
	}
	if ku.CertSign {
		x509ku |= x509.KeyUsageCertSign
	}
	if ku.CRLSign {
		x509ku |= x509.KeyUsageCRLSign
	}
	if ku.EncipherOnly {
		x509ku |= x509.KeyUsageEncipherOnly
	}
	if ku.DecipherOnly {
		x509ku |= x509.KeyUsageDecipherOnly
	}
	return x509ku
}

// Flattened Subject, mirrors crypto/x509/pkix/Name
type Subject struct {
	Country            string `json:"country"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	Locality           string `json:"locality"`
	Province           string `json:"province"`
	StreetAddress      string `json:"streetAddress"`
	PostalCode         string `json:"postalCode"`
	SerialNumber       string `json:"serialNumber"`
	CommonName         string `json:"commonName"`
}

func ToSubject(name pkix.Name) Subject {
	subject := Subject{
		SerialNumber: name.SerialNumber,
		CommonName:   name.CommonName,
	}
	if len(name.Country) > 0 {
		subject.Country = name.Country[0]
	}
	if len(name.Organization) > 0 {
		subject.Organization = name.Organization[0]
	}
	if len(name.OrganizationalUnit) > 0 {
		subject.OrganizationalUnit = name.OrganizationalUnit[0]
	}
	if len(name.Locality) > 0 {
		subject.Locality = name.Locality[0]
	}
	if len(name.Province) > 0 {
		subject.Province = name.Province[0]
	}
	if len(name.StreetAddress) > 0 {
		subject.StreetAddress = name.StreetAddress[0]
	}
	if len(name.PostalCode) > 0 {
		subject.PostalCode = name.PostalCode[0]
	}
	return subject
}

func (s *Subject) ToX509PKIXName() pkix.Name {
	var name pkix.Name
	if len(s.Country) > 0 {
		name.Country = []string{s.Country}
	}
	if len(s.Organization) > 0 {
		name.Organization = []string{s.Organization}
	}
	if len(s.OrganizationalUnit) > 0 {
		name.OrganizationalUnit = []string{s.OrganizationalUnit}
	}
	if len(s.Locality) > 0 {
		name.Locality = []string{s.Locality}
	}
	if len(s.Province) > 0 {
		name.Province = []string{s.Province}
	}
	if len(s.StreetAddress) > 0 {
		name.StreetAddress = []string{s.StreetAddress}
	}
	if len(s.PostalCode) > 0 {
		name.PostalCode = []string{s.PostalCode}
	}
	name.SerialNumber = s.SerialNumber
	name.CommonName = s.CommonName

	return name
}

// byte arrays and simliar are converted to base64 by the default GO
// json implementation. Since we typically just want to display
// signatures|keys|whatever format them as hex strings instead and
// provide translations. Also *big.Int which is used quite a bit,
// doesn't map to json at all.
type Hex string // TODO: add JSON unmarshal to check for valid values...

func (h *Hex) ToBytes() ([]byte, error) {
	return hex.DecodeString(string(*h))
}

func (h *Hex) ToBigInt() (*big.Int, error) {
	i := new(big.Int)
	b, err := hex.DecodeString(string(*h))
	if err != nil {
		return nil, err
	}
	return i.SetBytes(b), nil
}
func ToHex(i *big.Int) Hex {
	return (Hex)(hex.EncodeToString(i.Bytes()))
}

// This would be nice, but not supported by go currently:
// (to be more precise: of course it's supported, anonymous fields aren't
// mapped to json.)
//
//type certificate struct {
//	CertificateData
//	PublicKey PublicKey
//}

// This function takes a CA cert, CA keys, public keys, Certificate Data
// serving as a template and convert it all into a certificate.

func CreateCertificate(ca_cert *x509.Certificate,
	ca_key *rsa.PrivateKey,
	key_to_sign *rsa.PublicKey,
	data *CertificateData) (*x509.Certificate, error) {

	if data.SerialNumber == "" {
		data.SerialNumber = GeneratePubKeyHash(key_to_sign)
	}
	if data.SubjectKeyId == "" {
		data.SubjectKeyId = GeneratePubKeyHash(key_to_sign)
	}

	template, err := data.CreateX509Template()
	if err != nil {
		return nil, err
	}

	cert, err := x509.CreateCertificate(
		rand.Reader,
		template,
		ca_cert,
		key_to_sign,
		ca_key)

	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(cert)
}

// Turns flattened Certificate Data into x509.Certificate data to use
// internally.
func (data *CertificateData) CreateX509Template() (cert *x509.Certificate, err error) {

	// CreateCertificate creates a new X.509v3 certificate based on a template. The
	// following members of template are used:
	//
	//      - AuthorityKeyId
	//      - BasicConstraintsValid
	//      - CRLDistributionPoints
	//      - DNSNames
	//      - EmailAddresses
	//      - ExcludedDNSDomains
	//      - ExcludedEmailAddresses
	//      - ExcludedIPRanges
	//      - ExcludedURIDomains
	//      - ExtKeyUsage
	//      - ExtraExtensions
	//      - IPAddresses
	//      - IsCA
	//      - IssuingCertificateURL
	//      - KeyUsage
	//      - MaxPathLen
	//      - MaxPathLenZero
	//      - NotAfter
	//      - NotBefore
	//      - OCSPServer
	//      - PermittedDNSDomains
	//      - PermittedDNSDomainsCritical
	//      - PermittedEmailAddresses
	//      - PermittedIPRanges
	//      - PermittedURIDomains
	//      - PolicyIdentifiers
	//      - SerialNumber
	//      - SignatureAlgorithm
	//      - Subject
	//      - SubjectKeyId
	//      - URIs
	//      - UnknownExtKeyUsage
	//
	// The certificate is signed by parent. If parent is equal to template then the
	// certificate is self-signed. The parameter pub is the public key of the signee
	// and priv is the private key of the signer.

	cert = new(x509.Certificate)
	cert.SerialNumber, _ = data.SerialNumber.ToBigInt()
	cert.Subject = data.Subject.ToX509PKIXName()
	cert.NotBefore = data.NotBefore
	cert.NotAfter = data.NotAfter
	cert.KeyUsage = data.KeyUsage.toX509KeyUsage() // bitmap

	cert.BasicConstraintsValid = data.BasicConstraintsValid
	cert.IsCA = data.IsCA
	cert.MaxPathLen = data.MaxPathLen
	cert.SubjectKeyId, err = data.SubjectKeyId.ToBytes()
	cert.DNSNames = data.DNSNames
	cert.PermittedDNSDomainsCritical = data.PermittedDNSDomainsCritical
	cert.PermittedDNSDomains = data.PermittedDNSDomains
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// generates a sha512(256) hash over the
// Public Key modulus to serve as the serial number
// in the certificate.
// This is SHA-2 go 1.6 does not yet include SHA-3/keccak
// in the stdlib
func GeneratePubKeyHash(pubKey *rsa.PublicKey) Hex {
	pubKeyHash := sha512.Sum512_256(pubKey.N.Bytes())
	return Hex(hex.EncodeToString(pubKeyHash[:]))
}
