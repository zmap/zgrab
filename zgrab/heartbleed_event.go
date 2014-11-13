package zgrab

import (
	"encoding/json"
	"ztools/ztls"
)

type HeartbleedEvent struct {
	heartbleedLog *ztls.Heartbleed
}

var HeartbleedEventType = EventType{
	TypeName:         CONNECTION_EVENT_HEARTBLEED_NAME,
	GetEmptyInstance: newHeartbleedEvent,
}

func (h *HeartbleedEvent) GetType() EventType {
	return HeartbleedEventType
}

func (h *HeartbleedEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.heartbleedLog)
}

func (h *HeartbleedEvent) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, h.heartbleedLog)
}

func (h *HeartbleedEvent) HeartbleedLog() *ztls.Heartbleed {
	return h.heartbleedLog
}

func newHeartbleedEvent() EventData {
	return new(HeartbleedEvent)
}
