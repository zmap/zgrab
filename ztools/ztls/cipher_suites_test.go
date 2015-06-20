package ztls

import (
	"testing"

	. "gopkg.in/check.v1"
)

func TestCiphers(t *testing.T) { TestingT(t) }

type ZTLSCiphersSuite struct{}

var _ = Suite(&ZTLSCiphersSuite{})

func (s *ZTLSCiphersSuite) TestChromeCiphersImplemented(c *C) {
	for _, cipherID := range ChromeCiphers {
		supported := cipherIDInCipherList(cipherID, implementedCipherSuites)
		c.Check(supported, Equals, true, Commentf("Cipher %d (%s)", cipherID, nameForSuite(cipherID)))
	}
}

/*
func (s *ZTLSCiphersSuite) TestFirefoxCiphersImplemented(c *C) {
	for _, cipherID := range FirefoxCiphers {
		supported := cipherIDInCipherList(cipherID, implementedCipherSuites)
		c.Check(supported, Equals, true, Commentf("Cipher %d (%s)", cipherID, nameForSuite(cipherID)))
	}
}

func (s *ZTLSCiphersSuite) TestSafariCiphersImplemented(c *C) {
	for _, cipherID := range SafariCiphers {
		supported := cipherIDInCipherList(cipherID, implementedCipherSuites)
		c.Check(supported, Equals, true, Commentf("Cipher %d (%s)", cipherID, nameForSuite(cipherID)))
	}
}
*/
