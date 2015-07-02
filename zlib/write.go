/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zlib

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
