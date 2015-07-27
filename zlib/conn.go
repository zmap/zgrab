/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zlib

import (
	"bufio"
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

	"github.com/zmap/zgrab/ztools/ssh"
	"github.com/zmap/zgrab/ztools/x509"
	"github.com/zmap/zgrab/ztools/ztls"
)

var smtpEndRegex = regexp.MustCompile(`(?:^\d\d\d\s.*\r\n$)|(?:^\d\d\d-[\s\S]*\r\n\d\d\d\s.*\r\n$)`)
var pop3EndRegex = regexp.MustCompile(`(?:\r\n\.\r\n$)|(?:\r\n$)`)
var imapStatusEndRegex = regexp.MustCompile(`\r\n$`)
var ftpEndRegex = regexp.MustCompile(`^.*[0-9]{3}( [^\r\n]*)?\r?\n$`)

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

	onlyDHE             bool
	onlyExports         bool
	onlyExportsDH       bool
	chromeCiphers       bool
	chromeNoDHE         bool
	firefoxCiphers      bool
	firefoxNoDHECiphers bool
	safariCiphers       bool
	safariNoDHECiphers  bool
	noSNI               bool

	domain string

	// Encoding type
	ReadEncoding string

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

func (c *Conn) SetDHEOnly() {
	c.onlyDHE = true
}

func (c *Conn) SetExportsOnly() {
	c.onlyExports = true
}

func (c *Conn) SetExportsDHOnly() {
	c.onlyExportsDH = true
}

func (c *Conn) SetChromeCiphers() {
	c.chromeCiphers = true
}

func (c *Conn) SetChromeNoDHECiphers() {
	c.chromeNoDHE = true
}

func (c *Conn) SetFirefoxCiphers() {
	c.firefoxCiphers = true
}

func (c *Conn) SetFirefoxNoDHECiphers() {
	c.firefoxNoDHECiphers = true
}

func (c *Conn) SetSafariCiphers() {
	c.safariCiphers = true
}

func (c *Conn) SetSafariNoDHECiphers() {
	c.safariNoDHECiphers = true
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

func (c *Conn) HTTP(config *HTTPConfig) error {
	if len(config.ProxyDomain) > 0 {
		if err := c.doProxy(config); err != nil {
			return err
		}
	}
	return c.doHTTP(config)
}

func (c *Conn) makeHTTPRequest(config *HTTPConfig) (req *http.Request, encReq *HTTPRequest, err error) {
	if req, err = http.NewRequest(config.Method, "", nil); err != nil {
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
	req.Method = config.Method
	req.Proto = "HTTP/1.1"
	if c.isTls {
		url.Scheme = "https"
	} else {
		url.Scheme = "http"
	}
	url.Path = config.Endpoint
	req.URL = url
	var userAgent string
	if len(config.UserAgent) > 0 {
		userAgent = config.UserAgent
	} else {
		userAgent = "Mozilla/5.0 zgrab/0.x"
	}
	req.Header.Set("User-Agent", userAgent)
	encReq = new(HTTPRequest)
	encReq.Endpoint = config.Endpoint
	encReq.Method = config.Method
	encReq.UserAgent = userAgent
	return req, encReq, nil
}

func (c *Conn) sendHTTPRequestReadHTTPResponse(req *http.Request) (encRes *HTTPResponse, err error) {
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
		return
	}
	var body []byte
	if body, err = ioutil.ReadAll(res.Body); err != nil {
		return
	}
	encRes = new(HTTPResponse)
	encRes.StatusCode = res.StatusCode
	encRes.Body = string(body)
	encRes.Headers = HeadersFromGolangHeaders(res.Header)
	return encRes, nil
}

func (c *Conn) doProxy(config *HTTPConfig) error {
	req, encReq, err := c.makeHTTPRequest(config)
	if err != nil {
		return err
	}
	if c.grabData.HTTP == nil {
		c.grabData.HTTP = new(HTTPRequestResponse)
	}
	c.grabData.HTTP.ProxyRequest = encReq
	req.Method = "CONNECT"
	req.URL.Path = config.ProxyDomain
	encReq.Method = req.Method
	encReq.Endpoint = req.URL.Path
	var encRes *HTTPResponse
	if encRes, err = c.sendHTTPRequestReadHTTPResponse(req); err != nil {
		return err
	}
	c.grabData.HTTP.ProxyResponse = encRes
	return nil
}

func (c *Conn) doHTTP(config *HTTPConfig) error {
	req, encReq, err := c.makeHTTPRequest(config)
	if err != nil {
		return err
	}
	if c.grabData.HTTP == nil {
		c.grabData.HTTP = new(HTTPRequestResponse)
	}
	if len(config.ProxyDomain) > 0 {
		host := strings.Split(config.ProxyDomain, ":")[0]
		req.Host = host
		req.URL.Host = host
	}
	c.grabData.HTTP.Request = encReq
	var encRes *HTTPResponse
	if encRes, err = c.sendHTTPRequestReadHTTPResponse(req); err != nil {
		return err
	}
	c.grabData.HTTP.Response = encRes
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
	if !c.noSNI && c.domain != "" {
		tlsConfig.ServerName = c.domain
	}
	if c.onlyDHE {
		tlsConfig.CipherSuites = ztls.DHECiphers
	}
	if c.onlyExports {
		tlsConfig.CipherSuites = ztls.RSA512ExportCiphers
	}
	if c.onlyExportsDH {
		tlsConfig.CipherSuites = ztls.DHEExportCiphers
	}
	if c.chromeCiphers {
		tlsConfig.CipherSuites = ztls.ChromeCiphers
	}
	if c.chromeNoDHE {
		tlsConfig.CipherSuites = ztls.ChromeNoDHECiphers
	}
	if c.firefoxCiphers {
		tlsConfig.CipherSuites = ztls.FirefoxCiphers
	}
	if c.firefoxNoDHECiphers {
		tlsConfig.CipherSuites = ztls.FirefoxNoDHECiphers
	}

	if c.safariCiphers {
		tlsConfig.CipherSuites = ztls.SafariCiphers
		tlsConfig.ForceSuites = true
	}
	if c.safariNoDHECiphers {
		tlsConfig.CipherSuites = ztls.SafariNoDHECiphers
		tlsConfig.ForceSuites = true
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

func (c *Conn) readUntilRegex(res []byte, expr *regexp.Regexp) (int, error) {
	buf := res[0:]
	length := 0
	for finished := false; !finished; {
		n, err := c.getUnderlyingConn().Read(buf)
		length += n
		if err != nil {
			return length, err
		}
		if expr.Match(res[0:length]) {
			finished = true
		}
		if length == len(res) {
			return length, errors.New("Not enough buffer space")
		}
		buf = res[length:]
	}
	return length, nil
}

func (c *Conn) readSmtpResponse(res []byte) (int, error) {
	return c.readUntilRegex(res, smtpEndRegex)
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

func (c *Conn) readPop3Response(res []byte) (int, error) {
	return c.readUntilRegex(res, pop3EndRegex)
}

func (c *Conn) POP3Banner(b []byte) (int, error) {
	n, err := c.readPop3Response(b)
	c.grabData.Banner = string(b[0:n])
	return n, err
}

func (c *Conn) readImapStatusResponse(res []byte) (int, error) {
	return c.readUntilRegex(res, imapStatusEndRegex)
}

func (c *Conn) IMAPBanner(b []byte) (int, error) {
	n, err := c.readImapStatusResponse(b)
	c.grabData.Banner = string(b[0:n])
	return n, err
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

func (c *Conn) GetFTPBanner() error {
	res := make([]byte, 1024)
	n, err := c.readUntilRegex(res, ftpEndRegex)
	c.grabData.Banner = string(res[0:n])
	return err
}

func (c *Conn) SSHHandshake() error {
	config := c.sshScan.MakeConfig()
	client := ssh.Client(c.conn, config)
	err := client.ClientHandshake()
	handshakeLog := client.HandshakeLog()
	c.grabData.SSH = handshakeLog
	return err
}
