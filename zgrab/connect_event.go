package zgrab

import "encoding/json"

type ConnectEvent struct {
}

var ConnectEventType = EventType{
	TypeName:         CONNECTION_EVENT_CONNECT_NAME,
	GetEmptyInstance: newConnectEvent,
}

func (ce *ConnectEvent) GetType() EventType {
	return ConnectEventType
}

func (ce *ConnectEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(nil)
}

func (ce *ConnectEvent) UnmarshalJSON([]byte) error {
	return nil
}

func newConnectEvent() EventData {
	return new(ConnectEvent)
}
