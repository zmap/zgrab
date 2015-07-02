/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zlib

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

type ReadEvent struct {
	Response []byte
	encoding string
}

var ReadEventType = EventType{
	TypeName:         CONNECTION_EVENT_READ_NAME,
	GetEmptyInstance: func() EventData { return new(ReadEvent) },
}

func (r *ReadEvent) GetType() EventType {
	return ReadEventType
}

func (r *ReadEvent) encodeResponse() string {
	var enc string
	switch r.encoding {
	case "base64":
		enc = base64.StdEncoding.EncodeToString(r.Response)
	case "string":
		enc = string(r.Response)
	case "hex":
		enc = hex.EncodeToString(r.Response)
	default:
		enc = string(r.Response)
	}
	return enc
}

func (r *ReadEvent) MarshalJSON() ([]byte, error) {
	encodedResponse := r.encodeResponse()
	encoded := encodedReadEvent{
		Response: encodedResponse,
	}
	return json.Marshal(encoded)
}

func (r *ReadEvent) UnmarshalJSON(b []byte) error {
	var encoded encodedReadEvent
	if err := json.Unmarshal(b, &encoded); err != nil {
		return err
	}
	r.Response = []byte(encoded.Response)
	return nil
}

type encodedReadEvent struct {
	Response string `json:"response"`
}
