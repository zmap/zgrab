package zgrab

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func TestZGrabSuite(t *testing.T) { TestingT(t) }

type ZGrabSuite struct{}

var _ = Suite(&ZGrabSuite{})

func (s *ZGrabSuite) TestDecodeEmptyGrab(c *C) {
	g := new(Grab)
	g.Time = time.Unix(8675309, 0)
	g.Host = net.ParseIP("1.2.3.4")
	var d Grab
	marshalAndUnmarshal(g, &d, c)
}

func (s *ZGrabSuite) TestDecodeGrab(c *C) {
	g := new(Grab)
	g.Time = time.Unix(123456789, 0)
	g.Host = net.ParseIP("2.3.4.5")
	g.Log = make([]ConnectionEvent, 1)
	g.Log[0].Data = new(mockEventData).saneDefaults()
	var d Grab
	marshalAndUnmarshal(g, &d, c)
}

func marshalAndUnmarshal(original interface{}, target interface{}, c *C) {
	b, err := json.Marshal(original)
	c.Assert(err, IsNil)
	err = json.Unmarshal(b, target)
	c.Assert(err, IsNil)
	c.Check(target, DeepEquals, original)
}

type mockEventData struct {
	A string
	B int
	C *string
}

type encodedMockEvent struct {
	A string
	B int
	C *string
}

func newMockEvent() EventData {
	return new(mockEventData)
}

func (m *mockEventData) GetType() EventType {
	return mockEventType
}

func (m *mockEventData) MarshalJSON() ([]byte, error) {
	e := encodedMockEvent{
		A: m.A,
		B: m.B,
		C: m.C,
	}
	return json.Marshal(&e)
}

func (m *mockEventData) UnmarshalJSON(b []byte) error {
	e := encodedMockEvent{}
	if err := json.Unmarshal(b, &e); err != nil {
		return err
	}
	m.A = e.A
	m.B = e.B
	m.C = e.C
	return nil
}

func (m *mockEventData) saneDefaults() *mockEventData {
	m.A = "a"
	m.B = 123
	m.C = nil
	return m
}

var (
	mockEventType = EventType{
		TypeName:         "mock",
		GetEmptyInstance: newMockEvent,
	}
)

func init() {
	RegisterEventType(mockEventType)
}
