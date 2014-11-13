package zgrab

import (
	"encoding/json"
	"ztools/ztls"
)

// HandshakeEvent implements the EventData interface
type TLSHandshakeEvent struct {
	handshakeLog *ztls.ServerHandshake
}

func (he *TLSHandshakeEvent) GetType() EventType {
	return TLSHandshakeEventType
}

func (he *TLSHandshakeEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(he.handshakeLog)
}

func (he *TLSHandshakeEvent) UnmarshalJSON(b []byte) error {
	hs := new(ztls.ServerHandshake)
	if err := json.Unmarshal(b, hs); err != nil {
		return err
	}
	he.handshakeLog = hs
	return nil
}

func (he *TLSHandshakeEvent) GetHandshakeLog() *ztls.ServerHandshake {
	return he.handshakeLog
}

var (
	TLSHandshakeEventType = EventType{
		TypeName:         CONNECTION_EVENT_TLS_NAME,
		GetEmptyInstance: newTLSHandshakeEvent,
	}
)

func newTLSHandshakeEvent() EventData {
	return new(TLSHandshakeEvent)
}
