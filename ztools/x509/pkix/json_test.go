// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkix

import (
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/zmap/zgrab/ztools/zlog"
	. "gopkg.in/check.v1"
)

func TestJSON(t *testing.T) { TestingT(t) }

type JSONSuite struct {
	name             *Name
	ext              *Extension
	unknownAttribute AttributeTypeAndValue
}

var _ = Suite(&JSONSuite{})

func (s *JSONSuite) SetUpTest(c *C) {
	s.name = new(Name)
	s.name.CommonName = "davidadrian.org"
	s.name.SerialNumber = "12345678910"
	s.name.Country = []string{"US"}
	s.name.Organization = []string{"University of Michigan", "Computer Science Department"}
	s.name.Locality = []string{"Ann Arbor"}
	s.name.Province = []string{"MI"}

	s.name.Names = append(s.name.Names, AttributeTypeAndValue{Type: oidCountry, Value: s.name.Country[0]})
	s.name.Names = append(s.name.Names, AttributeTypeAndValue{Type: oidOrganization, Value: s.name.Organization[0]})
	s.name.Names = append(s.name.Names, AttributeTypeAndValue{Type: oidOrganization, Value: s.name.Organization[1]})
	s.name.Names = append(s.name.Names, AttributeTypeAndValue{Type: oidLocality, Value: s.name.Locality[0]})
	s.name.Names = append(s.name.Names, AttributeTypeAndValue{Type: oidProvince, Value: s.name.Province[0]})
	s.name.Names = append(s.name.Names, AttributeTypeAndValue{Type: oidCommonName, Value: s.name.CommonName})
	s.name.Names = append(s.name.Names, AttributeTypeAndValue{Type: oidSerialNumber, Value: s.name.SerialNumber})

	s.ext = new(Extension)
	s.ext.Id = oidCommonName
	s.ext.Critical = true
	s.ext.Value = []byte{1, 2, 3, 4, 5, 6, 7, 8}

	s.unknownAttribute.Type = asn1.ObjectIdentifier{1, 2, 3, 4}
	s.unknownAttribute.Value = "this is an unknown extension"
}

func (s *JSONSuite) TestEncodeDecodeName(c *C) {
	var encoded []byte
	var err error
	s.name.ExtraNames = append(s.name.Names, s.unknownAttribute)
	encoded, err = json.Marshal(s.name)
	c.Assert(err, IsNil)
	zlog.Info(string(encoded))
}

func (s *JSONSuite) TestEncodeDecodeExtension(c *C) {
	b, err := json.Marshal(s.ext)
	c.Assert(err, IsNil)
	fmt.Println(string(b))
}

func (s *JSONSuite) TestEncodeDecodeAuxOID(c *C) {
	var oid AuxOID = []int{1, 2, 1122, 45, 8}
	b, errEnc := json.Marshal(&oid)
	c.Assert(errEnc, IsNil)
	c.Assert(b, Not(IsNil))
	c.Assert(len(b) > 0, Equals, true)
	var dec AuxOID
	errDec := json.Unmarshal(b, &dec)
	c.Assert(errDec, IsNil)
	c.Check(dec.Equal(&oid), Equals, true)
}

func (s *JSONSuite) TestNegativeOIDFailsNicely(c *C) {
	var b = []byte("\"1.2.-88.5\"")
	var aux AuxOID
	errDecNeg := json.Unmarshal(b, &aux)
	c.Assert(errDecNeg, ErrorMatches, `Invalid OID integer -\d+`)
}

func (s *JSONSuite) TestInvalidOIDFailsNicely(c *C) {
	var b = []byte("\"1.aa4\"")
	var aux AuxOID
	errDecASCII := json.Unmarshal(b, &aux)
	c.Assert(errDecASCII, ErrorMatches, `Invalid OID integer aa4`)
	b = []byte("\"1..3\"")
	errDecMissing := json.Unmarshal(b, &aux)
	c.Assert(errDecMissing, ErrorMatches, `Invalid OID integer \d*`)
}

func (s *JSONSuite) TestMarshalJSON(c *C) {
	json, err := s.name.MarshalJSON()
	c.Assert(err, IsNil)
	c.Assert(string(json), Equals, "{\"common_name\":[\"davidadrian.org\"],\"country\":[\"US\"],\"locality\":[\"Ann Arbor\"],\"organization\":[\"University of Michigan\",\"Computer Science Department\"],\"province\":[\"MI\"],\"serial_number\":[\"12345678910\"]}")
}

func (s *JSONSuite) TestUnmarshalJSON(c *C) {
	var newName Name
	jsonStr := "{\"common_name\":[\"davidadrian.org\"],\"country\":[\"US\"],\"locality\":[\"Ann Arbor\"],\"organization\":[\"University of Michigan\",\"Computer Science Department\"],\"province\":[\"MI\"],\"serial_number\":[\"12345678910\"]}"
	err := newName.UnmarshalJSON([]byte(jsonStr))
	c.Assert(err, IsNil)
	c.Assert(newName, DeepEquals, *s.name)
}

func (s *JSONSuite) TestMarshalUnmarshalJSON(c *C) {
	json, err := s.name.MarshalJSON()
	c.Assert(err, IsNil)
	jsonStr := string(json)
	var newName Name
	err = newName.UnmarshalJSON([]byte(jsonStr))
	c.Assert(err, IsNil)
	c.Assert(newName, DeepEquals, *s.name)
}
