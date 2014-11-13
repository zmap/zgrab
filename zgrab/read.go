package zgrab

import "encoding/json"

type ReadEvent struct {
	Response []byte
	Error    error
}

var ReadEventType = EventType{
	TypeName:         CONNECTION_EVENT_READ_NAME,
	GetEmptyInstance: newReadEvent,
}

func (r *ReadEvent) GetType() EventType {
	return ReadEventType
}

func (r *ReadEvent) MarshalJSON() ([]byte, error) {
	encoded := encodedReadEvent{
		Response: r.Response,
		Error:    errorToStringPointer(r.Error),
	}
	return json.Marshal(encoded)
}

func (r *ReadEvent) UnmarshalJSON(b []byte) error {
	var encoded encodedReadEvent
	if err := json.Unmarshal(b, &encoded); err != nil {
		return err
	}
	r.Response = encoded.Response
	r.Error = stringPointerToError(encoded.Error)
	return nil
}

type encodedReadEvent struct {
	Response []byte  `json:"response"`
	Error    *string `json:"error"`
}

func newReadEvent() EventData {
	return new(ReadEvent)
}
