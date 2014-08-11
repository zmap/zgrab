package banner

import (
	"../zcrypto/ztls"
	"net"
	"fmt"
	"time"
)

// Implements the net.Conn interface
type Conn struct {
	// Underlying network connection
	conn net.Conn
	tlsConn ztls.Conn
	isTls bool

	// Keep track of state / network operations
	operations []ConnectionState

	// Cache the deadlines so we can reapply after TLS handshake
	readDeadline time.Time
	writeDeadline time.Time

}

func (c *Conn) getUnderlyingConn() (net.Conn) {
	if c.isTls {
		return c.tlsConn
	}
	return c.net.Conn
}

// Layer in the regular conn methods
func (c *Conn) LocalAddr() net.Addr {
	return c.getUnderlyingConn().LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.getUnderlyingConn().RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) {
	c.readDeadline = t
	c.writeDeadline = t
	return c.getUnderlyingConn().SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return c.getUnderlyingConn().SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = deadline
	return c.getUnderlyingConn().SetWriteDeadline(t)
}

// Delegate here, but record all the things
func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.getUnderlyingConn().Write(b)
	ws := writeState{toSend: b, err: err}
	operations = append(operations, []ConnectionState{ws})
	return n, err
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.getUnderlyingConn().Read(b)
	rs := readState{response: b[0:n], err: err}
	operations = append(operations, []ConnectionState{rs})
	return n, err
}

// Extra method - Do a TLS Handshake and record progress
func (c *Conn) TlsHandshake() error {
	if isTls {
		return fmt.Errorf(
			"Attempted repeat handshake with remote host %s",
			c.RemoteAddr().String())
	}
	tlsConfig := new(ztls.Config)
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.MinVersion = ztls.VersionSSL30
	c.tlsConn = ztls.Client(nconn, tlsConfig)
	c.tlsConn.SetReadDeadline(c.readDeadline)
	c.tlsConn.SetWriteDeadline(c.writeDeadline)
	c.isTls = true
	err := tlsConn.Handshake()
	return err
}

// Do a STARTTLS handshake
func (c *Conn) StarttlsHandshake() error {
	// Don't doublehandshake
	if isTls {
		return fmt.Errorf(
			"Attempt STARTTLS after TLS handshake with remote host %s",
			c.RemoteAddr().String())
	}
	// Send the STARTTLS message
	starttls := []byte("STARTTLS\r\n");
	ss := starttlsState{}
 	_, err := conn.Write(starttls);
	// Read the response on a successful send
	if err == nil {
		var n int
		buf := make([]byte, 256)
		n, err = conn.Read(buf)
		ss.response = buf[0:n]
	}
	// No matter what happened, record the state
	ss.err = err
	operations = append(operations, []ConnectionState{ss})
	// Stop if we failed already
	if err != nil {
		return err
	}
	// Successful so far, attempt to do the actual handshake
	return c.TlsHandshake()
}
