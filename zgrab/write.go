package zgrab

import "encoding/json"

type WriteEvent struct {
	Sent  []byte
	Error error
}

var WriteEventType = EventType{
	TypeName:         CONNECTION_EVENT_WRITE_NAME,
	GetEmptyInstance: newWriteEvent,
}

func (w *WriteEvent) GetType() EventType {
	return WriteEventType
}

func (w *WriteEvent) MarshalJSON() ([]byte, error) {
	encoded := encodedWriteEvent{
		Sent: w.Sent,
	}
	return json.Marshal(encoded)
}

func (w *WriteEvent) UnmarshalJSON(b []byte) error {
	var encoded encodedWriteEvent
	if err := json.Unmarshal(b, &encoded); err != nil {
		return err
	}
	w.Sent = encoded.Sent
	return nil
}

type encodedWriteEvent struct {
	Sent []byte `json:"sent"`
}

func newWriteEvent() EventData {
	return new(WriteEvent)
}
