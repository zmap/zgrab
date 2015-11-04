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
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/zmap/zgrab/ztools/ftp"
	"github.com/zmap/zgrab/ztools/processing"
)

type GrabTarget struct {
	Addr   net.IP
	Domain string
}

type grabTargetDecoder struct {
	reader *csv.Reader
}

func (gtd *grabTargetDecoder) DecodeNext() (interface{}, error) {
	record, err := gtd.reader.Read()
	if err != nil {
		return nil, err
	}
	if len(record) < 1 {
		return nil, errors.New("Invalid grab target (no fields)")
	}
	var target GrabTarget
	target.Addr = net.ParseIP(record[0])
	if target.Addr == nil {
		return nil, fmt.Errorf("Invalid IP address %s", record[0])
	}
	// Check for a domain
	if len(record) >= 2 {
		target.Domain = record[1]
	}
	return target, nil
}

func NewGrabTargetDecoder(reader io.Reader) processing.Decoder {
	csvReader := csv.NewReader(reader)
	d := grabTargetDecoder{
		reader: csvReader,
	}
	return &d
}

func makeDialer(c *Config) func(string) (*Conn, error) {
	proto := "tcp"
	timeout := c.Timeout
	return func(addr string) (*Conn, error) {
		deadline := time.Now().Add(timeout)
		d := Dialer{
			Deadline: deadline,
		}
		conn, err := d.Dial(proto, addr)
		conn.maxTlsVersion = c.TLSVersion
		if err == nil {
			conn.SetDeadline(deadline)
		}
		return conn, err
	}
}

func makeGrabber(config *Config) func(*Conn) error {
	// Do all the hard work here
	g := func(c *Conn) error {
		banner := make([]byte, 1024)
		response := make([]byte, 65536)
		c.SetCAPool(config.RootCAPool)
		if config.DHEOnly {
			c.SetDHEOnly()
		}
		if config.ExportsOnly {
			c.SetExportsOnly()
		}
		if config.ExportsDHOnly {
			c.SetExportsDHOnly()
		}
		if config.ChromeOnly {
			c.SetChromeCiphers()
		}
		if config.ChromeNoDHE {
			c.SetChromeNoDHECiphers()
		}
		if config.FirefoxOnly {
			c.SetFirefoxCiphers()
		}
		if config.FirefoxNoDHE {
			c.SetFirefoxNoDHECiphers()
		}
		if config.SafariOnly {
			c.SetSafariCiphers()
		}
		if config.SafariNoDHE {
			c.SetSafariNoDHECiphers()
		}
		if config.NoSNI {
			c.SetNoSNI()
		}
		if config.TLSExtendedRandom {
			c.SetExtendedRandom()
		}

		if config.SSH.SSH {
			c.sshScan = &config.SSH
		}
		c.ReadEncoding = config.Encoding
		if config.TLS {
			if err := c.TLSHandshake(); err != nil {
				c.erroredComponent = "tls"
				return err
			}
		}
		if config.Banners {
			if config.SMTP {
				if _, err := c.SMTPBanner(banner); err != nil {
					c.erroredComponent = "banner"
					return err
				}
			} else if config.POP3 {
				if _, err := c.POP3Banner(banner); err != nil {
					c.erroredComponent = "banner"
					return err
				}
			} else if config.IMAP {
				if _, err := c.IMAPBanner(banner); err != nil {
					c.erroredComponent = "banner"
					return err
				}
			} else {
				if _, err := c.BasicBanner(); err != nil {
					c.erroredComponent = "banner"
					return err
				}
			}
		}

		if config.FTP {
			c.grabData.FTP = new(ftp.FTPLog)

			is200Banner, err := ftp.GetFTPBanner(c.grabData.FTP, c.getUnderlyingConn())
			if err != nil {
				c.erroredComponent = "ftp"
				return err
			}

			if config.FTPAuthTLS && is200Banner {
				if err := c.GetFTPSCertificates(); err != nil {
					c.erroredComponent = "ftp-authtls"
					return err
				}
			}
		}

		if len(config.HTTP.Endpoint) > 0 {
			if err := c.HTTP(&config.HTTP); err != nil {
				c.erroredComponent = "http"
				return err
			}
		}

		if config.SSH.SSH {
			if err := c.SSHHandshake(); err != nil {
				c.erroredComponent = "ssh"
				return err
			}
		}

		if config.SendData {
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			msg := bytes.Replace(config.Data, []byte("%s"), []byte(host), -1)
			msg = bytes.Replace(msg, []byte("%d"), []byte(c.domain), -1)
			if _, err := c.Write(msg); err != nil {
				c.erroredComponent = "write"
				return err
			}
			if _, err := c.Read(response); err != nil {
				c.erroredComponent = "read"
				return err
			}
		}

		if config.EHLO {
			if err := c.EHLO(config.EHLODomain); err != nil {
				c.erroredComponent = "ehlo"
				return err
			}
		}
		if config.SMTPHelp {
			if err := c.SMTPHelp(); err != nil {
				c.erroredComponent = "smtp_help"
				return err
			}
		}
		if config.StartTLS {
			if config.IMAP {
				if err := c.IMAPStartTLSHandshake(); err != nil {
					c.erroredComponent = "starttls"
					return err
				}
			} else if config.POP3 {
				if err := c.POP3StartTLSHandshake(); err != nil {
					c.erroredComponent = "starttls"
					return err
				}
			} else {
				if err := c.SMTPStartTLSHandshake(); err != nil {
					c.erroredComponent = "starttls"
					return err
				}
			}
		}

		if config.Modbus {
			if _, err := c.SendModbusEcho(); err != nil {
				c.erroredComponent = "modbus"
				return err
			}
		}

		if config.Heartbleed {
			buf := make([]byte, 256)
			if _, err := c.CheckHeartbleed(buf); err != nil {
				c.erroredComponent = "heartbleed"
				return err
			}
		}
		return nil
	}
	// Wrap the whole thing in a logger
	return func(c *Conn) error {
		err := g(c)
		if err != nil {
			config.ErrorLog.Errorf("Conversation error with remote host %s: %s",
				c.RemoteAddr().String(), err.Error())
		}
		return err
	}
}

func GrabBanner(config *Config, target *GrabTarget) *Grab {
	dial := makeDialer(config)
	grabber := makeGrabber(config)
	port := strconv.FormatUint(uint64(config.Port), 10)
	addr := target.Addr.String()
	rhost := net.JoinHostPort(addr, port)
	t := time.Now()
	conn, dialErr := dial(rhost)
	if target.Domain != "" {
		conn.SetDomain(target.Domain)
	}
	if dialErr != nil {
		// Could not connect to host
		config.ErrorLog.Errorf("Could not connect to %s remote host %s: %s",
			target.Domain, addr, dialErr.Error())
		return &Grab{
			IP:             target.Addr,
			Domain:         target.Domain,
			Time:           t,
			Error:          dialErr,
			ErrorComponent: "connect",
		}
	}
	err := grabber(conn)
	return &Grab{
		IP:             target.Addr,
		Domain:         target.Domain,
		Time:           t,
		Data:           conn.grabData,
		Error:          err,
		ErrorComponent: conn.erroredComponent,
	}
}
