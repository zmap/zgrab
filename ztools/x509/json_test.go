package x509

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
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
	var err error
	s.pemData, err = ioutil.ReadFile("testdata/davidadrian.org.cert")
	c.Assert(err, IsNil)
	block, _ := pem.Decode(s.pemData)
	c.Assert(block, NotNil)
	s.rawCert = block.Bytes
	s.parsedCert, err = ParseCertificate(s.rawCert)
	c.Assert(err, IsNil)
}

func (s *JSONSuite) TestEncodeCertificate(c *C) {
	b, err := json.Marshal(s.parsedCert)
	c.Assert(err, IsNil)
	fmt.Println(string(b))
}
