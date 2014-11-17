package zlib

import "encoding/json"

type ReadEvent struct {
	Response []byte
}

var ReadEventType = EventType{
	TypeName:         CONNECTION_EVENT_READ_NAME,
	GetEmptyInstance: func() EventData { return new(ReadEvent) },
}

func (r *ReadEvent) GetType() EventType {
	return ReadEventType
}

func (r *ReadEvent) MarshalJSON() ([]byte, error) {
	encoded := encodedReadEvent{
		Response: r.Response,
	}
	return json.Marshal(encoded)
}

func (r *ReadEvent) UnmarshalJSON(b []byte) error {
	var encoded encodedReadEvent
	if err := json.Unmarshal(b, &encoded); err != nil {
		return err
	}
	r.Response = encoded.Response
	return nil
}

type encodedReadEvent struct {
	Response []byte `json:"response"`
}
