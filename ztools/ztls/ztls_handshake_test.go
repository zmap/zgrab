package ztls

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type ZTLSHandshakeSuite struct{}

var _ = Suite(&ZTLSHandshakeSuite{})

func (s *ZTLSHandshakeSuite) TestDecodeHello(c *C) {
	sh := new(ServerHello)
	sh.saneDefaults()
	var d ServerHello
	marshalAndUnmarshal(sh, &d, c)
}

func (s *ZTLSHandshakeSuite) TestDecodeHelloComplicated(c *C) {
	sh := new(ServerHello)
	sh.saneDefaults()
	sh.Version = VersionSSL30
	sh.OcspStapling = true
	sh.HeartbeatSupported = true
	var d ServerHello
	marshalAndUnmarshal(sh, &d, c)
}

func (s *ZTLSHandshakeSuite) TestEncodeCertificate(c *C) {
	sc := new(Certificates)
	b, encodingErr := json.Marshal(sc)
	c.Assert(encodingErr, IsNil)
	ec := new(encodedCertificates)
	decodingErr := json.Unmarshal(b, ec)
	c.Assert(decodingErr, IsNil)
	c.Check(ec.Issuer, IsNil)
	c.Check(ec.AltNames, IsNil)
	c.Check(ec.CommonName, IsNil)
	c.Check(ec.ValidationError, IsNil)
}

func (s *ZTLSHandshakeSuite) TestDecodeCertificate(c *C) {
	sc := new(Certificates)
	sc.saneDefaults()
	var d Certificates
	marshalAndUnmarshal(sc, &d, c)
}

func (s *ZTLSHandshakeSuite) TestDecodeCertificateComplicated(c *C) {
	sc := new(Certificates)
	sc.saneDefaults()
	sc.Certificates = make([][]byte, 2)
	for idx, cert := range getValidCertChainBase64() {
		sc.Certificates[idx], _ = base64.StdEncoding.DecodeString(cert)
	}
	sc.Issuer = "Example CA"
	sc.CommonName = "example.com"
	sc.AltNames = []string{"www.example.com", "example.com"}
	var d Certificates
	marshalAndUnmarshal(sc, &d, c)
}

func (s *ZTLSHandshakeSuite) TestDecodeHandshake(c *C) {
	h := new(ServerHandshake).saneDefaults()
	var d ServerHandshake
	marshalAndUnmarshal(h, &d, c)
}

func (s *ZTLSHandshakeSuite) TestDecodeEmptyHandshake(c *C) {
	h := new(ServerHandshake)
	var d ServerHandshake
	marshalAndUnmarshal(h, &d, c)
}

func (sh *ServerHello) saneDefaults() *ServerHello {
	sh.Version = VersionTLS12
	sh.Random = make([]byte, 32)
	io.ReadFull(rand.Reader, sh.Random)
	sh.SessionID = nil
	sh.CipherSuite = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	sh.CompressionMethod = 0
	sh.OcspStapling = false
	sh.TicketSupported = false
	sh.HeartbeatSupported = false
	return sh
}

func (c *Certificates) saneDefaults() *Certificates {
	c.Certificates = make([][]byte, 0)
	c.Valid = false
	c.ValidationError = errors.New("Certificate chain does not exist")
	return c
}

func (skx *ServerKeyExchange) saneDefaults() *ServerKeyExchange {
	skx.Key = make([]byte, 8)
	io.ReadFull(rand.Reader, skx.Key)
	return skx
}

func (sf *Finished) saneDefaults() *Finished {
	sf.VerifyData = make([]byte, 4)
	io.ReadFull(rand.Reader, sf.VerifyData)
	return sf
}

func (h *ServerHandshake) saneDefaults() *ServerHandshake {
	h.ServerHello = new(ServerHello).saneDefaults()
	h.ServerCertificates = new(Certificates).saneDefaults()
	h.ServerKeyExchange = new(ServerKeyExchange).saneDefaults()
	h.ServerFinished = new(Finished).saneDefaults()
	return h
}

func marshalAndUnmarshal(original interface{}, target interface{}, c *C) {
	b, err := json.Marshal(original)
	c.Assert(err, IsNil)
	err = json.Unmarshal(b, target)
	c.Assert(err, IsNil)
	c.Check(target, DeepEquals, original)
}

func getValidCertChainBase64() []string {
	return []string{"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"}
}
