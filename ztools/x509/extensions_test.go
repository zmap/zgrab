// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	. "gopkg.in/check.v1"
)

func TestExtensions(t *testing.T) { TestingT(t) }

type ExtensionsSuite struct {
	pemData     []byte
	rawCert     []byte
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
		if !strings.HasSuffix(test.Name(), ".cert") {
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

func (s *ExtensionsSuite) TestEncodeDecodeIAN(c *C) {
	for _, cert := range s.parsedCerts {
		if cert.Issuer.CommonName != "IAN Test" {
			continue
		}
		jsonExtensions, _ := cert.jsonifyExtensions()

		b, err := json.Marshal(&jsonExtensions.IssuerAltName)
		c.Assert(err, IsNil)
		c.Assert(string(b), Equals, `{"dns_names":["example.1.com","example.2.com"],"email_addresses":["test@iantest.com","test2@iantest2.com"],"ip_addresses":["1.2.3.4"],"other_names":[{"id":"1.2.3.4","value":"DCBEQlZ6YjIxbElHOTBhR1Z5SUdsa1pXNTBhV1pwWlhJPQ=="}],"registered_ids":["1.2.3.4"],"uniform_resource_identifiers":["http://www.insecure.com"]}`)

		ian := &GeneralNames{}
		err = ian.UnmarshalJSON(b)
		c.Assert(err, IsNil)
		c.Assert(jsonExtensions.IssuerAltName.DirectoryNames, DeepEquals, ian.DirectoryNames)
		c.Assert(jsonExtensions.IssuerAltName.DNSNames, DeepEquals, ian.DNSNames)
		c.Assert(jsonExtensions.IssuerAltName.EDIPartyNames, DeepEquals, ian.EDIPartyNames)
		c.Assert(jsonExtensions.IssuerAltName.EmailAddresses, DeepEquals, ian.EmailAddresses)
		c.Assert(jsonExtensions.IssuerAltName.RegisteredIDs, DeepEquals, ian.RegisteredIDs)
		c.Assert(jsonExtensions.IssuerAltName.URIs, DeepEquals, ian.URIs)
		c.Assert(jsonExtensions.IssuerAltName.IPAddresses, HasLen, len(ian.IPAddresses))
		c.Assert(jsonExtensions.IssuerAltName.IPAddresses[0].String(), Equals, ian.IPAddresses[0].String())

		c.Assert(jsonExtensions.IssuerAltName.OtherNames, HasLen, len(ian.OtherNames))
		c.Assert(jsonExtensions.IssuerAltName.OtherNames[0].Typeid, DeepEquals, ian.OtherNames[0].Typeid)
		c.Assert(jsonExtensions.IssuerAltName.OtherNames[0].Value.Tag, DeepEquals, ian.OtherNames[0].Value.Tag)
		c.Assert(jsonExtensions.IssuerAltName.OtherNames[0].Value.Class, DeepEquals, ian.OtherNames[0].Value.Class)
		c.Assert(jsonExtensions.IssuerAltName.OtherNames[0].Value.Bytes, DeepEquals, ian.OtherNames[0].Value.Bytes)
	}
}

func (s *ExtensionsSuite) TestEncodeDecodeSAN(c *C) {
	for _, cert := range s.parsedCerts {
		if cert.Issuer.CommonName != "SAN Test" {
			continue
		}

		jsonExtensions, _ := cert.jsonifyExtensions()

		b, err := json.Marshal(&jsonExtensions.SubjectAltName)
		c.Assert(err, IsNil)
		c.Assert(string(b), Equals, `{"directory_names":[{"common_name":["My Name"],"country":["US"],"organization":["My Organization"],"organizational_unit":["My Unit"]}],"dns_names":["dns1.test.com","dns2.test.com"],"email_addresses":["email@testsan.com"],"ip_addresses":["1.2.3.4"],"other_names":[{"id":"1.2.3.4","value":"DBVzb21lIG90aGVyIGlkZW50aWZpZXI="}],"registered_ids":["1.2.3.4"],"uniform_resource_identifiers":["http://watchit.com/"]}`)

		san := &GeneralNames{}
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
		if cert.Issuer.CommonName != "Name constraint" {
			continue
		}
		jsonExtensions, _ := cert.jsonifyExtensions()
		b, err := json.Marshal(&jsonExtensions.NameConstraints)
		c.Assert(err, IsNil)
		c.Assert(string(b), Equals, `{"critical":false,"permitted_email_addresses":["email","LulMail"],"permitted_directory_names":[{"common_name":["uiuc.net"],"country":["US"],"locality":["Champaign"],"organization":["UIUC"],"organizational_unit":["ECE"],"postal_code":["61820"],"province":["IL"],"street_address":["601 Wright St"]}],"permitted_registred_id":["1.2.3.4"],"excluded_names":["banned.com"],"excluded_ip_addresses":["192.168.1.1/16"]}`)
		nc := &NameConstraints{}
		err = nc.UnmarshalJSON(b)
		c.Assert(err, IsNil)
		c.Assert(jsonExtensions.NameConstraints.PermittedDirectoryNames, DeepEquals, nc.PermittedDirectoryNames)
		c.Assert(jsonExtensions.NameConstraints.PermittedDNSDomains, DeepEquals, nc.PermittedDNSDomains)
		c.Assert(jsonExtensions.NameConstraints.PermittedEdiPartyNames, DeepEquals, nc.PermittedEdiPartyNames)
		c.Assert(jsonExtensions.NameConstraints.PermittedRegisteredIDs, DeepEquals, nc.PermittedRegisteredIDs)
		c.Assert(jsonExtensions.NameConstraints.PermittedEmailDomains, DeepEquals, nc.PermittedEmailDomains)
		c.Assert(jsonExtensions.NameConstraints.PermittedIPAddresses, HasLen, len(nc.PermittedIPAddresses))

		c.Assert(jsonExtensions.NameConstraints.ExcludedDirectoryNames, DeepEquals, nc.ExcludedDirectoryNames)
		c.Assert(jsonExtensions.NameConstraints.ExcludedDNSDomains, DeepEquals, nc.ExcludedDNSDomains)
		c.Assert(jsonExtensions.NameConstraints.ExcludedEdiPartyNames, DeepEquals, nc.ExcludedEdiPartyNames)
		c.Assert(jsonExtensions.NameConstraints.ExcludedRegisteredIDs, DeepEquals, nc.ExcludedRegisteredIDs)
		c.Assert(jsonExtensions.NameConstraints.ExcludedEmailDomains, DeepEquals, nc.ExcludedEmailDomains)
		c.Assert(jsonExtensions.NameConstraints.ExcludedIPAddresses[0].Data.IP.String(), Equals, nc.ExcludedIPAddresses[0].Data.IP.String())
		c.Assert(jsonExtensions.NameConstraints.ExcludedIPAddresses[0].Data.Mask.String(), Equals, nc.ExcludedIPAddresses[0].Data.Mask.String())

		if len(nc.ExcludedIPAddresses) > 0 {
			c.Assert(jsonExtensions.NameConstraints.ExcludedIPAddresses[0].Data.IP.String(), Equals, nc.ExcludedIPAddresses[0].Data.IP.String())
			c.Assert(jsonExtensions.NameConstraints.ExcludedIPAddresses[0].Data.Mask.String(), Equals, nc.ExcludedIPAddresses[0].Data.Mask.String())
		}
	}
}
