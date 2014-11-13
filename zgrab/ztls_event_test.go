package zgrab

import (
	"testing"

	. "gopkg.in/check.v1"
)

func TestZTLSEventSuite(t *testing.T) { TestingT(t) }

type ZTLSEventSuite struct{}

var _ = Suite(&ZTLSEventSuite{})

func (s *ZTLSEventSuite) TestTLSTypeName(c *C) {
	c.Check(TLSHandshakeEventType.TypeName, Equals, CONNECTION_EVENT_TLS_NAME)
	t, err := EventTypeFromName(CONNECTION_EVENT_TLS_NAME)
	c.Check(err, IsNil)
	c.Check(t.TypeName, Equals, TLSHandshakeEventType.TypeName)
}
