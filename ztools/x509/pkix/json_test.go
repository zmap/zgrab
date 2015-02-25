package pkix

import (
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/zmap/ztools/zlog"
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
