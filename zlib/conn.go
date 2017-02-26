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
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zmap/zgrab/ztools/ftp"
	"github.com/zmap/zgrab/ztools/scada/bacnet"
	"github.com/zmap/zgrab/ztools/ssh"
	"github.com/zmap/zgrab/ztools/util"
	"github.com/zmap/zgrab/ztools/x509"
	"github.com/zmap/zgrab/ztools/ztls"
)

var smtpEndRegex = regexp.MustCompile(`(?:^\d\d\d\s.*\r\n$)|(?:^\d\d\d-[\s\S]*\r\n\d\d\d\s.*\r\n$)`)
var pop3EndRegex = regexp.MustCompile(`(?:\r\n\.\r\n$)|(?:\r\n$)`)
var imapStatusEndRegex = regexp.MustCompile(`\r\n$`)

const (
	SMTP_COMMAND = "STARTTLS\r\n"
	POP3_COMMAND = "STLS\r\n"
	IMAP_COMMAND = "a001 STARTTLS\r\n"
)

// Implements the net.Conn interface
type Conn struct {
	// Underlying network connection
	conn    net.Conn
	tlsConn *ztls.Conn
	isTls   bool

	grabData GrabData

	// Max TLS version
	maxTlsVersion uint16

	// Cache the deadlines so we can reapply after TLS handshake
	readDeadline  time.Time
	writeDeadline time.Time

	caPool *x509.CertPool

	CipherSuites                  []uint16
	ForceSuites                   bool
	noSNI                         bool
	ExternalClientHello           []byte
	extendedRandom                bool
	gatherSessionTicket           bool
	offerExtendedMasterSecret     bool
	tlsVerbose                    bool
	SignedCertificateTimestampExt bool

	domain string

	// SSH
	sshScan *SSHScanConfig

	// Errored component
	erroredComponent string
}

func (c *Conn) getUnderlyingConn() net.Conn {
	if c.isTls {
		return c.tlsConn
	}
	return c.conn
}

func (c *Conn) SetExternalClientHello(clientHello []byte) {
	c.ExternalClientHello = clientHello
}

func (c *Conn) SetExtendedRandom() {
	c.extendedRandom = true
}

func (c *Conn) SetCAPool(pool *x509.CertPool) {
	c.caPool = pool
}

func (c *Conn) SetDomain(domain string) {
	c.domain = domain
}

func (c *Conn) SetNoSNI() {
	c.noSNI = true
}

func (c *Conn) SetGatherSessionTicket() {
	c.gatherSessionTicket = true
}

func (c *Conn) SetOfferExtendedMasterSecret() {
	c.offerExtendedMasterSecret = true
}

func (c *Conn) SetSignedCertificateTimestampExt() {
	c.SignedCertificateTimestampExt = true
}

func (c *Conn) SetTLSVerbose() {
	c.tlsVerbose = true
}

// Layer in the regular conn methods
func (c *Conn) LocalAddr() net.Addr {
	return c.getUnderlyingConn().LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.getUnderlyingConn().RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return c.getUnderlyingConn().SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return c.getUnderlyingConn().SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return c.getUnderlyingConn().SetWriteDeadline(t)
}

// Delegate here, but record all the things
func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.getUnderlyingConn().Write(b)
	c.grabData.Write = string(b[0:n])
	return n, err
}

func (c *Conn) BasicBanner() (string, error) {
	b := make([]byte, 1024)
	n, err := c.getUnderlyingConn().Read(b)
	c.grabData.Banner = string(b[0:n])
	return c.grabData.Banner, err
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.getUnderlyingConn().Read(b)
	c.grabData.Read = string(b[0:n])
	return n, err
}

func (c *Conn) Close() error {
	return c.getUnderlyingConn().Close()
}

func (c *Conn) makeHTTPRequest(endpoint string, httpMethod string, userAgent string) (req *http.Request, encReq *HTTPRequest, err error) {
	if req, err = http.NewRequest(httpMethod, "", nil); err != nil {
		return
	}
	url := new(url.URL)
	var host string
	if len(c.domain) > 0 {
		host = c.domain
	} else {
		host, _, _ = net.SplitHostPort(c.RemoteAddr().String())
	}
	url.Host = host
	req.Host = host
	req.Method = httpMethod
	req.Proto = "HTTP/1.1"
	if c.isTls {
		url.Scheme = "https"
	} else {
		url.Scheme = "http"
	}
	url.Path = endpoint
	req.URL = url

	if len(userAgent) <= 0 {
		userAgent = "Mozilla/5.0 zgrab/0.x"
	}

	req.Header.Set("User-Agent", userAgent)
	encReq = new(HTTPRequest)
	encReq.Endpoint = endpoint
	encReq.Method = httpMethod
	encReq.UserAgent = userAgent
	return req, encReq, nil
}

func (c *Conn) makeHTTPRequestFromConfig(config *HTTPConfig) (req *http.Request, encReq *HTTPRequest, err error) {
	return c.makeHTTPRequest(config.Endpoint, config.Method, config.UserAgent)
}

func (c *Conn) sendHTTPRequestReadHTTPResponse(req *http.Request, config *HTTPConfig) (encRes *HTTPResponse, err error) {
	uc := c.getUnderlyingConn()
	if err = req.Write(uc); err != nil {
		return
	}
	if req.Method == "CONNECT" {
		req.Method = "HEAD" // fuck you golang
	}
	reader := bufio.NewReader(uc)
	var res *http.Response
	if res, err = http.ReadResponse(reader, req); err != nil {
		msg := err.Error()
		if len(msg) > 1024*config.MaxSize {
			err = errors.New(msg[0 : 1024*config.MaxSize])
		}
		return
	}
	var body []byte
	if body, err = ioutil.ReadAll(res.Body); err != nil {
		msg := err.Error()
		if len(msg) > 1024*config.MaxSize {
			err = errors.New(msg[0 : 1024*config.MaxSize])
		}
		return
	}
	encRes = new(HTTPResponse)
	encRes.StatusCode = res.StatusCode
	encRes.StatusLine = res.Proto + " " + res.Status
	encRes.VersionMajor = res.ProtoMajor
	encRes.VersionMinor = res.ProtoMinor
	//	encRes.Headers = HeadersFromGolangHeaders(res.Header)
	var bodyOutput []byte
	if len(body) > 1024*config.MaxSize {
		bodyOutput = body[0 : 1024*config.MaxSize]
	} else {
		bodyOutput = body
	}
	encRes.Body = string(bodyOutput)
	if len(bodyOutput) > 0 {
		m := sha256.New()
		m.Write(bodyOutput)
		encRes.BodySHA256 = m.Sum(nil)
	}
	return encRes, nil
}

func (c *Conn) doProxy(config *HTTPConfig) error {
	req, encReq, err := c.makeHTTPRequestFromConfig(config)
	if err != nil {
		return err
	}
	if c.grabData.HTTP == nil {
		c.grabData.HTTP = new(HTTP)
	}
	c.grabData.HTTP.ProxyRequest = encReq
	req.Method = "CONNECT"
	req.URL.Path = config.ProxyDomain
	encReq.Method = req.Method
	encReq.Endpoint = req.URL.Path
	var encRes *HTTPResponse
	if encRes, err = c.sendHTTPRequestReadHTTPResponse(req, config); err != nil {
		return err
	}
	c.grabData.HTTP.ProxyResponse = encRes
	if encRes.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy connect returned status %d", encRes.StatusCode)
	}
	return nil
}

// Extra method - Do a TLS Handshake and record progress
func (c *Conn) TLSHandshake() error {
	if c.isTls {
		return fmt.Errorf(
			"Attempted repeat handshake with remote host %s",
			c.RemoteAddr().String())
	}
	tlsConfig := new(ztls.Config)
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.MinVersion = ztls.VersionSSL30
	tlsConfig.MaxVersion = c.maxTlsVersion
	tlsConfig.RootCAs = c.caPool
	tlsConfig.HeartbeatEnabled = true
	tlsConfig.ClientDSAEnabled = true
	tlsConfig.ForceSuites = c.ForceSuites
	tlsConfig.CipherSuites = c.CipherSuites
	if !c.noSNI && c.domain != "" {
		tlsConfig.ServerName = c.domain
	}
	if c.extendedRandom {
		tlsConfig.ExtendedRandom = true
	}
	if c.SignedCertificateTimestampExt {
		tlsConfig.SignedCertificateTimestampExt = true
	}
	if c.gatherSessionTicket {
		tlsConfig.ForceSessionTicketExt = true
	}
	if c.offerExtendedMasterSecret {
		tlsConfig.ExtendedMasterSecret = true
	}
	if c.ExternalClientHello != nil {
		tlsConfig.ExternalClientHello = c.ExternalClientHello
	}

	c.tlsConn = ztls.Client(c.conn, tlsConfig)
	c.tlsConn.SetReadDeadline(c.readDeadline)
	c.tlsConn.SetWriteDeadline(c.writeDeadline)
	c.isTls = true
	err := c.tlsConn.Handshake()
	if tlsConfig.ForceSuites && err == ztls.ErrUnimplementedCipher {
		err = nil
	}
	hl := c.tlsConn.GetHandshakeLog()

	if !c.tlsVerbose {
		hl.KeyMaterial = nil
		hl.ClientHello = nil
		hl.ClientFinished = nil
		hl.ClientKeyExchange = nil
	}

	c.grabData.TLSHandshake = hl
	return err
}

func (c *Conn) sendStartTLSCommand(command string) error {
	// Don't doublehandshake
	if c.isTls {
		return fmt.Errorf(
			"Attempt STARTTLS after TLS handshake with remote host %s",
			c.RemoteAddr().String())
	}
	// Send the STARTTLS message
	starttls := []byte(command)
	_, err := c.conn.Write(starttls)
	return err
}

// Do a STARTTLS handshake
func (c *Conn) SMTPStartTLSHandshake() error {

	// Send the command
	if err := c.sendStartTLSCommand(SMTP_COMMAND); err != nil {
		return err
	}
	// Read the response on a successful send
	buf := make([]byte, 256)
	n, err := c.readSmtpResponse(buf)
	c.grabData.StartTLS = string(buf[0:n])

	// Actually check return code
	if n < 5 {
		err = errors.New("Server did not indicate support for STARTTLS")
	}
	if err == nil {
		var ret int
		ret, err = strconv.Atoi(c.grabData.StartTLS[0:3])
		if err != nil || ret < 200 || ret >= 300 {
			err = errors.New("Bad return code for STARTTLS")
		}
	}

	// Stop if we failed already
	if err != nil {
		return err
	}

	// Successful so far, attempt to do the actual handshake
	return c.TLSHandshake()
}

func (c *Conn) POP3StartTLSHandshake() error {
	if err := c.sendStartTLSCommand(POP3_COMMAND); err != nil {
		return err
	}

	buf := make([]byte, 512)
	n, err := c.readPop3Response(buf)
	c.grabData.StartTLS = string(buf[0:n])
	if err == nil {
		if !strings.HasPrefix(c.grabData.StartTLS, "+") {
			err = errors.New("Server did not indicate support for STARTTLS")
		}
	}

	if err != nil {
		return err
	}
	return c.TLSHandshake()
}

func (c *Conn) IMAPStartTLSHandshake() error {
	if err := c.sendStartTLSCommand(IMAP_COMMAND); err != nil {
		return err
	}

	buf := make([]byte, 512)
	n, err := c.readImapStatusResponse(buf)
	c.grabData.StartTLS = string(buf[0:n])
	if err == nil {
		if !strings.HasPrefix(c.grabData.StartTLS, "a001 OK") {
			err = errors.New("Server did not indicate support for STARTTLS")
		}
	}

	if err != nil {
		return err
	}
	return c.TLSHandshake()
}

func (c *Conn) readSmtpResponse(res []byte) (int, error) {
	return util.ReadUntilRegex(c.getUnderlyingConn(), res, smtpEndRegex)
}

func (c *Conn) SMTPBanner(b []byte) (int, error) {
	n, err := c.readSmtpResponse(b)
	c.grabData.Banner = string(b[0:n])
	return n, err
}

func (c *Conn) EHLO(domain string) error {
	cmd := []byte("EHLO " + domain + "\r\n")
	if _, err := c.getUnderlyingConn().Write(cmd); err != nil {
		return err
	}

	buf := make([]byte, 512)
	n, err := c.readSmtpResponse(buf)
	c.grabData.EHLO = string(buf[0:n])
	return err
}

func (c *Conn) SMTPHelp() error {
	cmd := []byte("HELP\r\n")
	h := new(SMTPHelpEvent)
	if _, err := c.getUnderlyingConn().Write(cmd); err != nil {
		c.grabData.SMTPHelp = h
		return err
	}
	buf := make([]byte, 512)
	n, err := c.readSmtpResponse(buf)
	h.Response = string(buf[0:n])
	c.grabData.SMTPHelp = h
	return err
}

func (c *Conn) SMTPQuit() error {
	cmd := []byte("QUIT\r\n")
	_, err := c.getUnderlyingConn().Write(cmd)
	return err
}

func (c *Conn) readPop3Response(res []byte) (int, error) {
	return util.ReadUntilRegex(c.getUnderlyingConn(), res, pop3EndRegex)
}

func (c *Conn) POP3Banner(b []byte) (int, error) {
	n, err := c.readPop3Response(b)
	c.grabData.Banner = string(b[0:n])
	return n, err
}

func (c *Conn) POP3Quit() error {
	cmd := []byte("QUIT\r\n")
	_, err := c.getUnderlyingConn().Write(cmd)
	return err
}

func (c *Conn) readImapStatusResponse(res []byte) (int, error) {
	return util.ReadUntilRegex(c.getUnderlyingConn(), res, imapStatusEndRegex)
}

func (c *Conn) IMAPBanner(b []byte) (int, error) {
	n, err := c.readImapStatusResponse(b)
	c.grabData.Banner = string(b[0:n])
	return n, err
}

func (c *Conn) IMAPQuit() error {
	cmd := []byte("a001 CLOSE\r\n")
	_, err := c.getUnderlyingConn().Write(cmd)
	return err
}

func (c *Conn) CheckHeartbleed(b []byte) (int, error) {
	if !c.isTls {
		return 0, fmt.Errorf(
			"Must perform TLS handshake before sending Heartbleed probe to %s",
			c.RemoteAddr().String())
	}
	n, err := c.tlsConn.CheckHeartbleed(b)
	hb := c.tlsConn.GetHeartbleedLog()
	if err == ztls.HeartbleedError {
		err = nil
	}
	c.grabData.Heartbleed = hb
	return n, err
}

func (c *Conn) BACNetVendorQuery() error {
	c.grabData.BACNet = new(bacnet.Log)
	if err := c.grabData.BACNet.QueryDeviceID(c.getUnderlyingConn()); err != nil {
		return err
	}
	if err := c.grabData.BACNet.QueryVendorNumber(c.getUnderlyingConn()); err != nil {
		return err
	}
	if err := c.grabData.BACNet.QueryVendorName(c.getUnderlyingConn()); err != nil {
		return err
	}
	if err := c.grabData.BACNet.QueryFirmwareRevision(c.getUnderlyingConn()); err != nil {
		return err
	}
	if err := c.grabData.BACNet.QueryApplicationSoftwareRevision(c.getUnderlyingConn()); err != nil {
		return err
	}
	if err := c.grabData.BACNet.QueryObjectName(c.getUnderlyingConn()); err != nil {
		return err
	}
	if err := c.grabData.BACNet.QueryModelName(c.getUnderlyingConn()); err != nil {
		return err
	}
	if err := c.grabData.BACNet.QueryDescription(c.getUnderlyingConn()); err != nil {
		return err
	}
	if err := c.grabData.BACNet.QueryLocation(c.getUnderlyingConn()); err != nil {
		return err
	}
	return nil
}

func (c *Conn) SendModbusEcho() (int, error) {
	req := ModbusRequest{
		Function: ModbusFunctionEncapsulatedInterface,
		Data: []byte{
			0x0E, // read device info
			0x01, // product code
			0x00, // object id, should always be 0 in initial request
		},
	}

	event := new(ModbusEvent)
	data, err := req.MarshalBinary()
	w := 0
	for w < len(data) {
		written, err := c.getUnderlyingConn().Write(data[w:]) // TODO verify write
		w += written
		if err != nil {
			c.grabData.Modbus = event
			return w, errors.New("Could not write modbus request")
		}
	}

	res, err := c.GetModbusResponse()
	event.Length = res.Length
	event.UnitID = res.UnitID
	event.Function = res.Function
	event.Response = res.Data
	event.ParseSelf()
	// make sure the whole thing gets appended to the operation log
	c.grabData.Modbus = event
	return w, err
}

func (c *Conn) GetFTPSCertificates() error {
	ftpsReady, err := ftp.SetupFTPS(c.grabData.FTP, c.getUnderlyingConn())

	if err != nil {
		return err
	}

	if ftpsReady {
		return c.TLSHandshake()
	} else {
		return nil
	}
}

func (c *Conn) SSHHandshake() error {
	config := c.sshScan.MakeConfig()
	client := ssh.Client(c.conn, config)
	err := client.ClientHandshake()
	handshakeLog := client.HandshakeLog()
	c.grabData.SSH = handshakeLog
	return err
}
