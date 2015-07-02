/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zlib

import (
	"encoding/json"

	"github.com/zmap/zgrab/ztools/ztls"
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
