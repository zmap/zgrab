package zgrab

import (
	"testing"

	. "gopkg.in/check.v1"
)

func TestEventSuite(t *testing.T) { TestingT(t) }

type EventSuite struct{}

var _ = Suite(&EventSuite{})

func (s *EventSuite) TestEventTypeFromName(c *C) {
	_, err := EventTypeFromName("does-not-exist")
	c.Check(err, NotNil)
}

func (s *EventSuite) TestConnectEventName(c *C) {
	t, err := EventTypeFromName(CONNECTION_EVENT_CONNECT_NAME)
	c.Check(err, IsNil)
	c.Check(t.TypeName, Equals, CONNECTION_EVENT_CONNECT_NAME)
}
