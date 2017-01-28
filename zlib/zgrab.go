/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package zlib

import (
	"encoding/json"
	"net"
	"time"

	"github.com/zmap/zgrab/ztools/ftp"
	"github.com/zmap/zgrab/ztools/scada/bacnet"
	"github.com/zmap/zgrab/ztools/scada/dnp3"
	"github.com/zmap/zgrab/ztools/scada/fox"
	"github.com/zmap/zgrab/ztools/scada/siemens"
	"github.com/zmap/zgrab/ztools/ssh"
	"github.com/zmap/zgrab/ztools/telnet"
	"github.com/zmap/zgrab/ztools/xssh"
	"github.com/zmap/zgrab/ztools/ztls"
)

type Grab struct {
	IP             net.IP
	Domain         string
	Time           time.Time
	Data           GrabData
	Error          error
	ErrorComponent string
}

type encodedGrab struct {
	IP             string    `json:"ip"`
	Domain         string    `json:"domain,omitempty"`
	Time           string    `json:"timestamp"`
	Data           *GrabData `json:"data,omitempty"`
	Error          *string   `json:"error,omitempty"`
	ErrorComponent string    `json:"error_component,omitempty"`
}

type GrabData struct {
	Banner       string                `json:"banner,omitempty"`
	Read         string                `json:"read,omitempty"`
	Write        string                `json:"write,omitempty"`
	EHLO         string                `json:"ehlo,omitempty"`
	SMTPHelp     *SMTPHelpEvent        `json:"smtp_help,omitempty"`
	StartTLS     string                `json:"starttls,omitempty"`
	TLSHandshake *ztls.ServerHandshake `json:"tls,omitempty"`
	HTTP         *HTTP                 `json:"http,omitempty"`
	Heartbleed   *ztls.Heartbleed      `json:"heartbleed,omitempty"`
	Modbus       *ModbusEvent          `json:"modbus,omitempty"`
	SSH          *ssh.HandshakeLog     `json:"ssh,omitempty"`
	XSSH         *xssh.HandshakeLog    `json:"xssh,omitempty"`
	FTP          *ftp.FTPLog           `json:"ftp,omitempty"`
	BACNet       *bacnet.Log           `json:"bacnet,omitempty"`
	Fox          *fox.FoxLog           `json:"fox,omitempty"`
	DNP3         *dnp3.DNP3Log         `json:"dnp3,omitempty"`
	S7           *siemens.S7Log        `json:"s7,omitempty"`
	Telnet       *telnet.TelnetLog     `json:"telnet,omitempty"`
}

func (g *Grab) MarshalJSON() ([]byte, error) {
	time := g.Time.Format(time.RFC3339)
	var errString *string
	if g.Error != nil {
		s := g.Error.Error()
		errString = &s
	}
	obj := encodedGrab{
		IP:             g.IP.String(),
		Domain:         g.Domain,
		Time:           time,
		Data:           &g.Data,
		Error:          errString,
		ErrorComponent: g.ErrorComponent,
	}
	return json.Marshal(obj)
}

func (g *Grab) UnmarshalJSON(b []byte) error {
	eg := new(encodedGrab)
	err := json.Unmarshal(b, eg)
	if err != nil {
		return err
	}
	g.IP = net.ParseIP(eg.IP)
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
