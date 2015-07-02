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
