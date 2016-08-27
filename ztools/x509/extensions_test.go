// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"testing"

	. "gopkg.in/check.v1"
)

func TestExtensions(t *testing.T) { TestingT(t) }

type ExtensionsSuite struct {
	pemData    []byte
	rawCert    []byte
	parsedCerts []Certificate
}

var _ = Suite(&ExtensionsSuite{})

func (s *ExtensionsSuite) SetUpTest(c *C) {
	tests, err := ioutil.ReadDir("testdata")

	if err != nil {
		fmt.Println(err)
		return
	}

	for _, test := range tests {
		if test.Name()[0] == 46 {
			continue
		}
		var err error
		var parsedCert *Certificate
		s.pemData, err = ioutil.ReadFile("testdata/" + test.Name())
		c.Assert(err, IsNil)
		block, _ := pem.Decode(s.pemData)
		c.Assert(block, NotNil)
		s.rawCert = block.Bytes
		parsedCert, err = ParseCertificate(s.rawCert)
		c.Assert(err, IsNil)
		s.parsedCerts = append(s.parsedCerts, *parsedCert)
	}
}

func (s *ExtensionsSuite) TestEncodeDecodeSAN(c *C) {
	for _, cert := range s.parsedCerts {
		if (cert.Issuer.CommonName != "SAN Test"){
			continue
		}

		jsonExtensions, _ := cert.jsonifyExtensions()

		b, err := json.Marshal(&jsonExtensions.SubjectAltName)
		c.Assert(err, IsNil)
		c.Assert(string(b), Equals, `{"directory_names":[{"common_name":["My Name"],"country":["US"],"organization":["My Organization"],"organizational_unit":["My Unit"]}],"dns_names":["dns1.test.com","dns2.test.com"],"email_addresses":["email@testsan.com"],"ip_addresses":["1.2.3.4"],"other_names":[{"id":"1.2.3.4","value":"DBVzb21lIG90aGVyIGlkZW50aWZpZXI="}],"registered_ids":["1.2.3.4"],"uniform_resource_identifiers":["http://watchit.com/"]}`)

		san := &SubjectAltName{}
		err = san.UnmarshalJSON(b)
		c.Assert(err, IsNil)
		c.Assert(jsonExtensions.SubjectAltName.DirectoryNames, DeepEquals, san.DirectoryNames)
		c.Assert(jsonExtensions.SubjectAltName.DNSNames, DeepEquals, san.DNSNames)
		c.Assert(jsonExtensions.SubjectAltName.EDIPartyNames, DeepEquals, san.EDIPartyNames)
		c.Assert(jsonExtensions.SubjectAltName.EmailAddresses, DeepEquals, san.EmailAddresses)
		c.Assert(jsonExtensions.SubjectAltName.RegisteredIDs, DeepEquals, san.RegisteredIDs)
		c.Assert(jsonExtensions.SubjectAltName.URIs, DeepEquals, san.URIs)
		// Somehow the IP address becomes IPv6 when unmarshaling, so no DeepEquals comparison
		c.Assert(jsonExtensions.SubjectAltName.IPAddresses, HasLen, len(san.IPAddresses))
		c.Assert(jsonExtensions.SubjectAltName.IPAddresses[0].String(), Equals, san.IPAddresses[0].String())
		// OtherNames.FullBytes is lost (should be able to reconstruct from RawValue fields)
		c.Assert(jsonExtensions.SubjectAltName.OtherNames, HasLen, len(san.OtherNames))
		c.Assert(jsonExtensions.SubjectAltName.OtherNames[0].Typeid, DeepEquals, san.OtherNames[0].Typeid)
		c.Assert(jsonExtensions.SubjectAltName.OtherNames[0].Value.Tag, DeepEquals, san.OtherNames[0].Value.Tag)
		c.Assert(jsonExtensions.SubjectAltName.OtherNames[0].Value.Class, DeepEquals, san.OtherNames[0].Value.Class)
		c.Assert(jsonExtensions.SubjectAltName.OtherNames[0].Value.Bytes, DeepEquals, san.OtherNames[0].Value.Bytes)
	}
}

func (s *ExtensionsSuite) TestEncodeDecodeNc(c *C) {
	for _, cert := range s.parsedCerts {
		if (cert.Issuer.CommonName != "Name constraint"){
			continue
		}
		jsonExtensions, _ := cert.jsonifyExtensions()
		b, err := json.Marshal(&jsonExtensions.NameConstraints)
		c.Assert(err, IsNil)
		c.Assert(string(b), Equals, `{"critical":false,"permitted_email_addresses":["email","LulMail"],"permitted_ip_addresses":["192.168.0.0/16"],"permitted_edi_party_names":[{"name_assigner":"assigner","party_name":"party"}],"permitted_registred_id":["1.2.3.4.2.2.3.4"],"excluded_names":["banned.com"],"excluded_directory_names":[{"common_name":["gov.us"],"country":["US"],"locality":["Tallahassee"],"organization":["Extreme Discord"],"organizational_unit":["Chaos"],"postal_code":["30062"],"province":["FL"],"street_address":["3210 Holly Mill Run"]}]}`)
		nc := &NameConstraints{}
		err = nc.UnmarshalJSON(b)
		c.Assert(err, IsNil) 
		c.Assert(jsonExtensions.NameConstraints.PermittedDirectoryNames, DeepEquals, nc.PermittedDirectoryNames)
		c.Assert(jsonExtensions.NameConstraints.PermittedDNSDomains, DeepEquals, nc.PermittedDNSDomains)
		c.Assert(jsonExtensions.NameConstraints.PermittedEdiPartyNames, DeepEquals, nc.PermittedEdiPartyNames)
		c.Assert(jsonExtensions.NameConstraints.PermittedRegisteredIDs, DeepEquals, nc.PermittedRegisteredIDs)
		c.Assert(jsonExtensions.NameConstraints.PermittedEmailDomains, DeepEquals, nc.PermittedEmailDomains)
		c.Assert(jsonExtensions.NameConstraints.PermittedIPAddresses, HasLen, len(nc.PermittedIPAddresses))
		c.Assert(jsonExtensions.NameConstraints.PermittedIPAddresses[0].Data.IP.String(), Equals, nc.PermittedIPAddresses[0].Data.IP.String())
		c.Assert(jsonExtensions.NameConstraints.PermittedIPAddresses[0].Data.Mask.String(), Equals, nc.PermittedIPAddresses[0].Data.Mask.String())

		c.Assert(jsonExtensions.NameConstraints.ExcludedDirectoryNames, DeepEquals, nc.ExcludedDirectoryNames)
		c.Assert(jsonExtensions.NameConstraints.ExcludedDNSDomains, DeepEquals, nc.ExcludedDNSDomains)
		c.Assert(jsonExtensions.NameConstraints.ExcludedEdiPartyNames, DeepEquals, nc.ExcludedEdiPartyNames)
		c.Assert(jsonExtensions.NameConstraints.ExcludedRegisteredIDs, DeepEquals, nc.ExcludedRegisteredIDs)
		c.Assert(jsonExtensions.NameConstraints.ExcludedEmailDomains, DeepEquals, nc.ExcludedEmailDomains)
		c.Assert(jsonExtensions.NameConstraints.ExcludedIPAddresses, HasLen, len(nc.ExcludedIPAddresses))
		if (len(nc.ExcludedIPAddresses) > 0) {
			c.Assert(jsonExtensions.NameConstraints.ExcludedIPAddresses[0].Data.IP.String(), Equals, nc.ExcludedIPAddresses[0].Data.IP.String())
			c.Assert(jsonExtensions.NameConstraints.ExcludedIPAddresses[0].Data.Mask.String(), Equals, nc.ExcludedIPAddresses[0].Data.Mask.String())
		}
	}
}
