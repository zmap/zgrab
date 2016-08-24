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

func (s *ExtensionsSuite) TestEncodeSAN(c *C) {
	for _, cert := range s.parsedCerts {
		if (cert.Issuer.CommonName != "SAN Test"){
			continue
		}

		jsonExtensions, _ := cert.jsonifyExtensions()

		b, err := json.Marshal(&jsonExtensions.SubjectAltName)
		c.Assert(err, IsNil)
		c.Assert(string(b), Equals, `{"directory_names":[{"common_name":["My Name"],"country":["US"],"organization":["My Organization"],"organizational_unit":["My Unit"]}],"dns_names":["dns1.test.com","dns2.test.com"],"email_addresses":["email@testsan.com"],"ip_addresses":["1.2.3.4"],"other_names":[{"id":"1.2.3.4","value":"DBVzb21lIG90aGVyIGlkZW50aWZpZXI="}],"registered_ids":["1.2.3.4"],"uniform_resource_identifiers":["http://watchit.com/"]}`)
	}
}
