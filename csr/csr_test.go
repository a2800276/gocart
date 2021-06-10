package csr_test

import "testing"
import "os"

import "crypto/x509/pkix"

import "github.com/a2800276/gocart/encoding/pem"

//import "github.com/a2800276/gocart/csr"

const csr_pem_file = "../test_cert/234.csr"

func TestLoadCSR(t *testing.T) {
	f, err := os.Open(csr_pem_file)
	if err != nil {
		t.Error("Can't open test pem", csr_pem_file, err)
	}

	csr, err := pem.DecodeCSRPEM(f)

	if err != nil {
		t.Error("Can't decode test pem", csr_pem_file, err)
	}
	name := pkix.Name{}
	name.FillFromRDNSequence(&csr.CertificationRequestInfo.Subject)
	subj := ToSubject(name)
	if subj.CommonName != "Timbob Spongelabs" {
		t.Error("CSR not properly decoded")
	}
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
