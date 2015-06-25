package keys

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	. "gopkg.in/check.v1"
)

func TestECDHE(t *testing.T) { TestingT(t) }

type ECDHESuite struct{}

var _ = Suite(&ECDHESuite{})

func (s *ECDHESuite) TestEncodeDecodeCurveID(c *C) {
	for curve := range ecIDToName {
		out, errEnc := json.Marshal(&curve)
		c.Assert(errEnc, IsNil)
		var back TLSCurveID
		errDec := json.Unmarshal(out, &back)
		c.Assert(errDec, IsNil)
		c.Check(back, Equals, curve)
	}
}

func (s *ECDHESuite) TestEncodeDecodeECPoint(c *C) {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(255), nil)
	max.Sub(max, big.NewInt(19))
	x, errX := rand.Int(rand.Reader, max)
	y, errY := rand.Int(rand.Reader, max)
	c.Assert(errX, IsNil)
	c.Assert(errY, IsNil)
	p := ECPoint{
		X: x,
		Y: y,
	}
	out, errEnc := json.Marshal(&p)
	c.Assert(errEnc, IsNil)
	c.Check(len(out), Not(Equals), 0)
	var back ECPoint
	errDec := json.Unmarshal(out, &back)
	c.Assert(errDec, IsNil)
}

func (s *ECDHESuite) TestCurveIDDescription(c *C) {
	for curve, name := range ecIDToName {
		c.Check(curve.Description(), Equals, name)
	}
	unk := TLSCurveID(6500)
	c.Check(unk.Description(), Equals, "unknown")
}

func (s *ECDHESuite) TestEncodeDecodeECParam(c *C) {
	ecp := new(ECDHParams)
	out, errEnc := json.Marshal(&ecp)
	c.Assert(errEnc, IsNil)
	c.Check(len(out), Not(Equals), 0)
	back := new(ECDHParams)
	errDec := json.Unmarshal(out, back)
	c.Assert(errDec, IsNil)
	c.Check(back, DeepEquals, ecp)
}
