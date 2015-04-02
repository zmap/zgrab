package ssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"

	"github.com/zmap/zgrab/ztools/zlog"
)

type Conn struct {
	// Underlying network connection
	conn net.Conn

	config Config

	// Key information
	macLength uint32

	// Log for ZGrab output
	handshakeLog HandshakeLog
}

func (c *Conn) ClientHandshake() error {
	clientProtocol := MakeZGrabProtocolAgreement()
	clientProtocolBytes := clientProtocol.Marshal()
	c.handshakeLog.ClientProtocol = clientProtocol
	c.conn.Write(clientProtocolBytes)

	buf := make([]byte, 1024)
	protocolDone := false
	protocolRead := 0
	for !protocolDone && protocolRead < 1024 {
		n, err := c.conn.Read(buf[protocolRead : protocolRead+1])
		protocolRead += n
		if err != nil {
			return err
		}
		if protocolRead < 2 {
			continue
		}
		if bytes.Equal(buf[protocolRead-2:protocolRead], []byte("\r\n")) {
			protocolDone = true
		}
	}
	serverProtocol := ProtocolAgreement{
		RawBanner: string(buf[0:protocolRead]),
	}
	serverProtocol.ParseRawBanner()
	c.handshakeLog.ServerProtocol = &serverProtocol

	// See if it matches????

	// Read the key options
	packet, err := c.readPacket()
	if err != nil {
		return err
	}
	serverKex, ok := packet.(*KeyExchangeInit)
	if !ok {
		return errUnexpectedMessage
	}
	c.handshakeLog.ServerKeyExchange = serverKex
	return nil
}

func (c *Conn) HandshakeLog() *HandshakeLog {
	return &c.handshakeLog
}

func (c *Conn) readPacket() (interface{}, error) {
	// Make a buffer of max packet size
	buf := make([]byte, 35001)
	totalRead, err := c.conn.Read(buf[0:4])
	if err != nil {
		return nil, err
	}
	for totalRead < 4 {
		n, err := c.conn.Read(buf[totalRead:4])
		totalRead += n
		if err != nil {
			return nil, err
		}
	}
	var p packet
	p.packetLength = binary.BigEndian.Uint32(buf[0:4])
	zlog.Debug(p.packetLength)
	if p.packetLength > 35000 {
		return nil, errLongPacket
	}
	totalLength := expectedLength(p.packetLength, c.macLength)
	for totalRead < totalLength {
		n, err := c.conn.Read(buf[totalRead:totalLength])
		totalRead += n
		if err != nil {
			return nil, err
		}
	}
	// Fill out the rest of the packet
	b := buf[4:totalLength]

	// Read padding length
	if len(b) < 1 {
		return nil, errShortPacket
	}
	p.paddingLength = b[0]
	b = b[1:]
	zlog.Debug(p.paddingLength)
	if uint32(p.paddingLength) > p.packetLength-1 {
		return nil, errInvalidPadding
	}

	// Read the payload
	payloadLength := p.packetLength - uint32(p.paddingLength) - 1
	zlog.Debug(payloadLength)
	p.payload = b[0:payloadLength]
	b = b[payloadLength:]

	// Read the padding
	p.padding = b[0:p.paddingLength]
	b = b[p.paddingLength:]

	// Read the MAC, if applicable
	if uint32(len(b)) != c.macLength {
		zlog.Debug(len(b))
		return nil, errShortPacket
	}

	if c.macLength > 0 {
		p.mac = b[0:c.macLength]
	}
	zlog.Debug(p)
	if len(p.payload) < 1 {
		return nil, errShortPacket
	}
	msgType := p.payload[0]
	switch msgType {
	case SSH_MSG_KEXINIT:
		var kxi KeyExchangeInit
		kxi.Unmarshal(p.payload[1:])
		return &kxi, nil
	}
	return nil, errors.New("unimplemented")
}
