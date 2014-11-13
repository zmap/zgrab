package zgrab

import (
	"crypto/x509"
	"fmt"
	"net"
	"regexp"
	"time"

	"ztools/ztls"
)

var smtpEndRegex = regexp.MustCompile(`(?:\r\n)|^[0-9]{3} .+\r\n$`)
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

	// Max TLS version
	maxTlsVersion uint16

	// Keep track of state / network operations
	operations []ConnectionEvent

	// Cache the deadlines so we can reapply after TLS handshake
	readDeadline  time.Time
	writeDeadline time.Time

	caPool  *x509.CertPool
	cbcOnly bool

	domain string
}

func (c *Conn) getUnderlyingConn() net.Conn {
	if c.isTls {
		return c.tlsConn
	}
	return c.conn
}

func (c *Conn) SetCbcOnly() {
	c.cbcOnly = true
}

func (c *Conn) SetCAPool(pool *x509.CertPool) {
	c.caPool = pool
}

func (c *Conn) SetDomain(domain string) {
	c.domain = domain
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
	w := WriteEvent{Sent: b}
	event := ConnectionEvent{
		Data:  &w,
		Error: err,
	}
	c.operations = append(c.operations, event)
	return n, err
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.getUnderlyingConn().Read(b)
	r := ReadEvent{Response: b[0:n]}
	event := ConnectionEvent{
		Data:  &r,
		Error: err,
	}
	c.operations = append(c.operations, event)
	return n, err
}

func (c *Conn) Close() error {
	return c.getUnderlyingConn().Close()
}

// Extra method - Do a TLS Handshake and record progress
func (c *Conn) TlsHandshake() error {
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
	if c.domain != "" {
		tlsConfig.ServerName = c.domain
	}
	c.tlsConn = ztls.Client(c.conn, tlsConfig)
	c.tlsConn.SetReadDeadline(c.readDeadline)
	c.tlsConn.SetWriteDeadline(c.writeDeadline)
	c.isTls = true
	err := c.tlsConn.Handshake()
	hl := c.tlsConn.GetHandshakeLog()
	ts := TLSHandshakeEvent{handshakeLog: hl}
	event := ConnectionEvent{
		Data:  &ts,
		Error: err,
	}
	c.operations = append(c.operations, event)
	return err
}

/*

func (c *Conn) sendStarttlsCommand(command string) error {
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
func (c *Conn) SmtpStarttlsHandshake() error {
	// Make the state
	ss := starttlsState{command: []byte(SMTP_COMMAND)}
	// Send the command
	ss.err = c.sendStarttlsCommand(SMTP_COMMAND)
	// Read the response on a successful send
	if ss.err == nil {
		buf := make([]byte, 256)
		n, err := c.readSmtpResponse(buf)
		ss.response = buf[0:n]
		ss.err = err
	}
	// No matter what happened, record the state
	c.operations = append(c.operations, &ss)
	// Stop if we failed already
	if ss.err != nil {
		return ss.err
	}
	// Successful so far, attempt to do the actual handshake
	return c.TlsHandshake()
}

func (c *Conn) Pop3StarttlsHandshake() error {
	ss := starttlsState{command: []byte(POP3_COMMAND)}
	ss.err = c.sendStarttlsCommand(POP3_COMMAND)
	if ss.err == nil {
		buf := make([]byte, 512)
		n, err := c.readPop3Response(buf)
		ss.response = buf[0:n]
		ss.err = err
	}
	c.operations = append(c.operations, &ss)
	if ss.err != nil {
		return ss.err
	}
	return c.TlsHandshake()
}

func (c *Conn) ImapStarttlsHandshake() error {
	ss := starttlsState{command: []byte(IMAP_COMMAND)}
	ss.err = c.sendStarttlsCommand(IMAP_COMMAND)
	if ss.err == nil {
		buf := make([]byte, 512)
		n, err := c.readImapStatusResponse(buf)
		ss.response = buf[0:n]
		ss.err = err
	}
	c.operations = append(c.operations, &ss)
	if ss.err != nil {
		return ss.err
	}
	return c.TlsHandshake()
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

func (c *Conn) SmtpBanner(b []byte) (int, error) {
	n, err := c.readSmtpResponse(b)
	rs := readState{}
	rs.response = b[0:n]
	rs.err = err
	c.operations = append(c.operations, &rs)
	return n, err
}

func (c *Conn) Ehlo(domain string) error {
	cmd := []byte("EHLO " + domain + "\r\n")
	es := ehloState{}
	_, writeErr := c.getUnderlyingConn().Write(cmd)
	if writeErr != nil {
		es.err = writeErr
	} else {
		buf := make([]byte, 512)
		n, readErr := c.readSmtpResponse(buf)
		es.err = readErr
		es.response = buf[0:n]
	}
	c.operations = append(c.operations, &es)
	return es.err
}

func (c *Conn) SmtpHelp() error {
	cmd := []byte("HELP\r\n")
	hs := helpState{}
	_, writeErr := c.getUnderlyingConn().Write(cmd)
	if writeErr != nil {
		hs.err = writeErr
	} else {
		buf := make([]byte, 512)
		n, readErr := c.readSmtpResponse(buf)
		hs.err = readErr
		hs.response = buf[0:n]
	}
	c.operations = append(c.operations, &hs)
	return hs.err
}

func (c *Conn) readPop3Response(res []byte) (int, error) {
	return c.readUntilRegex(res, pop3EndRegex)
}

func (c *Conn) Pop3Banner(b []byte) (int, error) {
	n, err := c.readPop3Response(b)
	rs := readState{
		response: b[0:n],
		err:      err,
	}
	c.operations = append(c.operations, &rs)
	return n, err
}

func (c *Conn) readImapStatusResponse(res []byte) (int, error) {
	return c.readUntilRegex(res, imapStatusEndRegex)
}

func (c *Conn) ImapBanner(b []byte) (int, error) {
	n, err := c.readImapStatusResponse(b)
	rs := readState{
		response: b[0:n],
		err:      err,
	}
	c.operations = append(c.operations, &rs)
	return n, err
}
*/

func (c *Conn) SendHeartbleedProbe(b []byte) (int, error) {
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
	event := ConnectionEvent{
		Data:  &HeartbleedEvent{heartbleedLog: hb},
		Error: err,
	}
	c.operations = append(c.operations, event)
	return n, err
}

func (c *Conn) States() []ConnectionEvent {
	return c.operations
}
