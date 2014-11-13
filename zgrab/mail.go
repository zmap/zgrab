package zgrab

import "encoding/json"

// An EHLOEvent represents the response to an EHLO
type EHLOEvent struct {
	Response []byte
	Error    error
}

var EHLOEventType = EventType{
	TypeName:         CONNECTION_EVENT_EHLO_NAME,
	GetEmptyInstance: newEHLOEvent,
}

type encodedEHLOEvent struct {
	Response []byte  `json:"response"`
	Error    *string `json:"error"`
}

func (e *EHLOEvent) GetType() EventType {
	return EHLOEventType
}

// MarshalJSON implements the json.Marshaler interface
func (e *EHLOEvent) MarshalJSON() ([]byte, error) {
	encoded := encodedEHLOEvent{
		Response: e.Response,
		Error:    errorToStringPointer(e.Error),
	}
	return json.Marshal(encoded)
}

// UnmarshalJSON implments the json.Unmarshal interface
func (e *EHLOEvent) UnmarshalJSON(b []byte) error {
	var encoded encodedEHLOEvent
	if err := json.Unmarshal(b, &encoded); err != nil {
		return err
	}
	e.Response = encoded.Response
	e.Error = stringPointerToError(encoded.Error)
	return nil
}

func newEHLOEvent() EventData {
	return new(EHLOEvent)
}
