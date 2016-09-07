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

func TestJSON(t *testing.T) { TestingT(t) }

type JSONSuite struct {
	pemData    []byte
	rawCert    []byte
	parsedCert *Certificate
}

var _ = Suite(&JSONSuite{})

func (s *JSONSuite) SetUpTest(c *C) {
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
		s.pemData, err = ioutil.ReadFile("testdata/" + test.Name())
		c.Assert(err, IsNil)
		block, _ := pem.Decode(s.pemData)
		c.Assert(block, NotNil)
		s.rawCert = block.Bytes
		s.parsedCert, err = ParseCertificate(s.rawCert)
		c.Assert(err, IsNil)
	}
}

func (s *JSONSuite) TestEncodeDecodeSignatureAlgorithmInt(c *C) {
	algo := SHA256WithRSA
	b, errEnc := json.Marshal(&algo)
	c.Assert(errEnc, IsNil)
	c.Assert(b, Not(IsNil))
	c.Assert(len(b) > 0, Equals, true)
	fmt.Println(string(b))
	var dec SignatureAlgorithm
	errDec := json.Unmarshal(b, &dec)
	c.Assert(errDec, IsNil)
	c.Check(dec, DeepEquals, algo)
}

func (s *JSONSuite) TestEncodeCertificate(c *C) {
	b, err := json.Marshal(s.parsedCert)
	c.Assert(err, IsNil)
	fmt.Println(string(b))
}
