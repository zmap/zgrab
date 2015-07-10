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
	"net"
	"time"
)

type Grab struct {
	Host   net.IP            `json:"host"`
	Domain string            `json:"domain"`
	Time   time.Time         `json:"timestamp"`
	Log    []ConnectionEvent `json:"log"`
}

type ConnectionEvent struct {
	Data  EventData
	Error error
}

type encodedGrab struct {
	Host   string                 `json:"host"`
	Domain *string                `json:"domain,omitempty"`
	Time   string                 `json:"time"`
	Data   map[string]interface{} `json:"grab"`
}

type encodedConnectionEvent struct {
	Data  EventData `json:"data"`
	Error *string   `json:"error"`
}

type partialConnectionEvent struct {
	Data  EventData `json:"data"`
	Error *string   `json:"error"`
}

func (ce *ConnectionEvent) MarshalJSON() ([]byte, error) {
	var esp *string
	if ce.Error != nil {
		es := ce.Error.Error()
		esp = &es
	}
	obj := encodedConnectionEvent{
		Data:  ce.Data,
		Error: esp,
	}
	return json.Marshal(obj)
}

func (ce *ConnectionEvent) UnmarshalJSON(b []byte) error {
	panic("unimplemented")
	return nil
}

func (g *Grab) MarshalJSON() ([]byte, error) {
	var domainPtr *string
	if g.Domain != "" {
		domainPtr = &g.Domain
	}
	time := g.Time.Format(time.RFC3339)
	obj := encodedGrab{
		Host:   g.Host.String(),
		Domain: domainPtr,
		Time:   time,
		Data:   make(map[string]interface{}, 2*len(g.Log)),
	}
	for idx, val := range g.Log {
		obj.Data[val.Data.GetType().TypeName] = &g.Log[idx]
	}
	return json.Marshal(obj)
}

func (g *Grab) UnmarshalJSON(b []byte) error {
	eg := new(encodedGrab)
	err := json.Unmarshal(b, eg)
	if err != nil {
		return err
	}
	g.Host = net.ParseIP(eg.Host)
	if eg.Domain != nil {
		g.Domain = *eg.Domain
	}
	if g.Time, err = time.Parse(time.RFC3339, eg.Time); err != nil {
		return err
	}
	panic("unimplemented")
	return nil
}

func (g *Grab) status() status {
	if len(g.Log) == 0 {
		return status_failure
	}
	for _, entry := range g.Log {
		if entry.Error != nil {
			return status_failure
		}
	}
	return status_success
}
