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

	"github.com/zmap/zgrab/ztools/ssh"
	"github.com/zmap/zgrab/ztools/ztls"
)

type Grab struct {
	Host   net.IP    `json:"host"`
	Domain string    `json:"domain"`
	Time   time.Time `json:"timestamp"`
	Data   GrabData  `json:"log"`
	Error  error     `json:"error,omitempty"`
}

type ConnectionEvent struct {
	Data  EventData
	Error error
}

type encodedGrab struct {
	Host   string    `json:"host"`
	Domain string    `json:"domain,omitempty"`
	Time   string    `json:"timestamp"`
	Data   *GrabData `json:"data"`
	Error  *string   `json:"error,omitempty"`
}

type GrabData struct {
	Banner       string                `json:"banner,omitempty"`
	Read         []byte                `json:"read,omitempty"`
	EHLO         *EHLOEvent            `json:"ehlo,omitempty"`
	SMTPHelp     *SMTPHelpEvent        `json:"smtp_help,omitempty"`
	StartTLS     *StartTLSEvent        `json:"starttls,omitempty"`
	TLSHandshake *ztls.ServerHandshake `json:"tls,omitempty"`
	Heartbleed   *ztls.Heartbleed      `json:"heartbleed,omitempty"`
	Modbus       *ModbusEvent          `json:"modbus,omitempty"`
	SSH          *ssh.HandshakeLog     `json:"ssh,omitempty"`
}

func (g *Grab) MarshalJSON() ([]byte, error) {
	time := g.Time.Format(time.RFC3339)
	var errString *string
	if g.Error != nil {
		s := g.Error.Error()
		errString = &s
	}
	obj := encodedGrab{
		Host:   g.Host.String(),
		Domain: g.Domain,
		Time:   time,
		Data:   &g.Data,
		Error:  errString,
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
	g.Domain = eg.Domain
	if g.Time, err = time.Parse(time.RFC3339, eg.Time); err != nil {
		return err
	}
	panic("unimplemented")
}

func (g *Grab) status() status {
	if g.Error != nil {
		return status_failure
	}
	return status_success
}
