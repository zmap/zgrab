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
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/zmap/zgrab/ztools/ftp"
	"github.com/zmap/zgrab/ztools/http"
	"github.com/zmap/zgrab/ztools/processing"
	"github.com/zmap/zgrab/ztools/scada/dnp3"
	"github.com/zmap/zgrab/ztools/scada/fox"
	"github.com/zmap/zgrab/ztools/scada/siemens"
	"github.com/zmap/zgrab/ztools/telnet"
	"github.com/zmap/zgrab/ztools/util"
	"github.com/zmap/zgrab/ztools/zlog"
	"github.com/zmap/zgrab/ztools/ztls"
	"io"
	"net"
	"strconv"
	"time"
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

type grabDomainDecoder struct {
	reader *bufio.Reader
}

func (gdd *grabDomainDecoder) DecodeNext() (interface{}, error) {
	record, err := gdd.reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	var target GrabTarget
	if record == nil {
		return nil, errors.New("No domains were found")
	}

	target.Domain = string(record[:len(record)-1])
	return target, nil
}

func NewGrabTargetDecoder(reader io.Reader, domainOnly bool) processing.Decoder {

	if domainOnly {
		domainReader := bufio.NewReader(reader)
		d := grabDomainDecoder{
			reader: domainReader,
		}
		return &d
	} else {
		csvReader := csv.NewReader(reader)
		d := grabTargetDecoder{
			reader: csvReader,
		}
		return &d
	}
}

func makeDialer(c *Config) func(string) (*Conn, error) {
	proto := "tcp"
	if c.BACNet {
		proto = "udp"
	}
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

func makeNetDialer(c *Config) func(string, string) (net.Conn, error) {
	proto := "tcp"
	timeout := c.Timeout
	return func(net, addr string) (net.Conn, error) {
		deadline := time.Now().Add(timeout)
		d := Dialer{
			Deadline: deadline,
		}
		conn, err := d.Dial(proto, addr)
		conn.maxTlsVersion = c.TLSVersion
		if err == nil {
			conn.SetDeadline(deadline)
		}
		return conn.getUnderlyingConn(), err
	}
}

func makeHTTPGrabber(config *Config, grabData GrabData) func(string, string, string) error {
	g := func(urlHost, endpoint, httpHost string) (err error) {

		var tlsConfig *ztls.Config
		if config.TLS || config.HTTP.MaxRedirects > 0 {
			tlsConfig = new(ztls.Config)
			tlsConfig.InsecureSkipVerify = true
			tlsConfig.MinVersion = ztls.VersionSSL30
			tlsConfig.MaxVersion = config.TLSVersion
			tlsConfig.RootCAPools = config.RootCAPools
			tlsConfig.HeartbeatEnabled = true
			tlsConfig.ClientDSAEnabled = true
			if config.DHEOnly {
				tlsConfig.CipherSuites = ztls.DHECiphers
			}
			if config.ECDHEOnly {
				tlsConfig.CipherSuites = ztls.ECDHECiphers
			}
			if config.ExportsOnly {
				tlsConfig.CipherSuites = ztls.RSA512ExportCiphers
			}
			if config.ExportsDHOnly {
				tlsConfig.CipherSuites = ztls.DHEExportCiphers
			}
			if config.ChromeOnly {
				tlsConfig.CipherSuites = ztls.ChromeCiphers
			}
			if config.ChromeNoDHE {
				tlsConfig.CipherSuites = ztls.ChromeNoDHECiphers
			}
			if config.FirefoxOnly {
				tlsConfig.CipherSuites = ztls.FirefoxCiphers
			}
			if config.FirefoxNoDHE {
				tlsConfig.CipherSuites = ztls.FirefoxNoDHECiphers
			}

			if config.SafariOnly {
				tlsConfig.CipherSuites = ztls.SafariCiphers
				tlsConfig.ForceSuites = true
			}
			if config.SafariNoDHE {
				tlsConfig.CipherSuites = ztls.SafariNoDHECiphers
				tlsConfig.ForceSuites = true
			}
			if config.TLSExtendedRandom {
				tlsConfig.ExtendedRandom = true
			}
			if config.GatherSessionTicket {
				tlsConfig.ForceSessionTicketExt = true
			}
			if !config.NoSNI && urlHost != "" {
				tlsConfig.ServerName = urlHost
			}

		}

		transport := &http.Transport{
			Proxy:               nil, // TODO: implement proxying
			Dial:                makeNetDialer(config),
			DisableKeepAlives:   false,
			DisableCompression:  false,
			MaxIdleConnsPerHost: -1,
			TLSClientConfig:     tlsConfig,
		}

		client := http.MakeNewClient()
		client.UserAgent = config.HTTP.UserAgent
		client.CheckRedirect = func(req *http.Request, res *http.Response, via []*http.Request) error {
			grabData.HTTP.RedirectResponseChain = append(grabData.HTTP.RedirectResponseChain, res)
			if str, err := util.ReadString(res.Body, config.HTTP.MaxSize*1024); err != nil {
				return err
			} else {
				res.BodyText = str
				m := sha256.New()
				m.Write([]byte(str))
				res.BodySHA256 = m.Sum(nil)
			}
			res.Body.Close()

			if len(via) > config.HTTP.MaxRedirects {
				return errors.New(fmt.Sprintf("stopped after %d redirects", config.HTTP.MaxRedirects))
			}

			return nil
		}
		client.Jar = nil // Don't send or receive cookies (otherwise use CookieJar)
		client.Transport = transport

		var fullURL string

		if config.TLS {
			fullURL = "https://" + urlHost + endpoint
		} else {
			fullURL = "http://" + urlHost + endpoint
		}

		var resp *http.Response
		switch config.HTTP.Method {
		case "GET":
			resp, err = client.GetWithHost(fullURL, httpHost)
		case "HEAD":
			resp, err = client.HeadWithHost(fullURL, httpHost)
		default:
			zlog.Fatalf("Bad HTTP Method: %s. Valid options are: GET, HEAD.", config.HTTP.Method)
		}

		if err != nil {
			config.ErrorLog.Errorf("Could not connect to remote host %s: %s", fullURL, err.Error())
			return err
		}

		grabData.HTTP.Response = resp

		if str, err := util.ReadString(resp.Body, config.HTTP.MaxSize*1024); err != nil {
			return err
		} else {
			grabData.HTTP.Response.BodyText = str
			m := sha256.New()
			m.Write([]byte(str))
			grabData.HTTP.Response.BodySHA256 = m.Sum(nil)
		}

		resp.Body.Close()

		return nil
	}

	return g
}

func makeGrabber(config *Config) func(*Conn) error {
	// Do all the hard work here
	g := func(c *Conn) error {
		banner := make([]byte, 1024)
		response := make([]byte, 65536)
		c.SetCAPools(config.RootCAPools)
		if config.DHEOnly {
			c.CipherSuites = ztls.DHECiphers
		}
		if config.ECDHEOnly {
			c.CipherSuites = ztls.ECDHECiphers
		}
		if config.ExportsOnly {
			c.CipherSuites = ztls.RSA512ExportCiphers
		}
		if config.ExportsDHOnly {
			c.CipherSuites = ztls.DHEExportCiphers
		}
		if config.ChromeOnly {
			c.CipherSuites = ztls.ChromeCiphers
		}
		if config.ChromeNoDHE {
			c.CipherSuites = ztls.ChromeNoDHECiphers
		}
		if config.FirefoxOnly {
			c.CipherSuites = ztls.FirefoxCiphers
		}
		if config.FirefoxNoDHE {
			c.CipherSuites = ztls.FirefoxNoDHECiphers
		}
		if config.SafariOnly {
			c.CipherSuites = ztls.SafariCiphers
			c.ForceSuites = true
		}
		if config.SafariNoDHE {
			c.CipherSuites = ztls.SafariNoDHECiphers
			c.ForceSuites = true
		}
		if config.NoSNI {
			c.SetNoSNI()
		}
		if config.TLSExtendedRandom {
			c.SetExtendedRandom()
		}
		if config.GatherSessionTicket {
			c.SetGatherSessionTicket()
		}
		if config.ExtendedMasterSecret {
			c.SetOfferExtendedMasterSecret()
		}
		if config.TLSVerbose {
			c.SetTLSVerbose()
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

		if config.Fox {
			c.grabData.Fox = new(fox.FoxLog)

			if err := fox.GetFoxBanner(c.grabData.Fox, c.getUnderlyingConn()); err != nil {
				c.erroredComponent = "fox"
				return err
			}
		}

		if config.Telnet {
			c.grabData.Telnet = new(telnet.TelnetLog)

			if err := telnet.GetTelnetBanner(c.grabData.Telnet, c.getUnderlyingConn(), config.TelnetMaxSize); err != nil {
				c.erroredComponent = "telnet"
				return err
			}
		}

		if config.S7 {
			c.grabData.S7 = new(siemens.S7Log)

			if err := siemens.GetS7Banner(c.grabData.S7, c.getUnderlyingConn()); err != nil {
				c.erroredComponent = "s7"
				return err
			}
		}

		if config.DNP3 {
			c.grabData.DNP3 = new(dnp3.DNP3Log)
			dnp3.GetDNP3Banner(c.grabData.DNP3, c.getUnderlyingConn())
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

		if config.BACNet {
			if err := c.BACNetVendorQuery(); err != nil {
				c.erroredComponent = "bacnet"
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

		c.Close()
		return err
	}
}

func GrabBanner(config *Config, target *GrabTarget) *Grab {

	if len(config.HTTP.Endpoint) == 0 {
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
	} else {
		grabData := GrabData{HTTP: new(HTTP)}
		httpGrabber := makeHTTPGrabber(config, grabData)
		port := strconv.FormatUint(uint64(config.Port), 10)
		t := time.Now()
		var rhost string
		if config.LookupDomain {
			rhost = target.Domain
		} else {
			rhost = net.JoinHostPort(target.Addr.String(), port)
		}

		err := httpGrabber(rhost, config.HTTP.Endpoint, target.Domain)

		return &Grab{
			IP:     target.Addr,
			Domain: target.Domain,
			Time:   t,
			Data:   grabData,
			Error:  err,
		}
	}
}
