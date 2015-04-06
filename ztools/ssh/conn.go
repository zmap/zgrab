package ssh

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"net"

	"github.com/zmap/zgrab/ztools/zlog"
)

type Conn struct {
	// Underlying network connection
	conn net.Conn

	config *Config

	// Key information
	macLength uint32

	// Log for ZGrab output
	handshakeLog HandshakeLog

	currentCipher cipher

	kexAlgorithm     string
	hostKeyAlgorithm string
}

type sshPayload interface {
	MsgType() byte
	Marshal() ([]byte, error)
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

	//
	ckxi, err := GenerateKeyExchangeInit(c.config)
	if err != nil {
		return err
	}
	if err = c.writePacket(ckxi); err != nil {
		return err
	}

	// Read the key options
	var packet interface{}
	packet, err = c.readPacket()
	if err != nil {
		return err
	}
	serverKex, ok := packet.(*KeyExchangeInit)
	if !ok {
		return errUnexpectedMessage
	}
	c.handshakeLog.ServerKeyExchangeInit = serverKex

	if c.kexAlgorithm, err = chooseAlgorithm(ckxi.KexAlgorithms, serverKex.KexAlgorithms); err != nil {
		return err
	}

	c.handshakeLog.Algorithms = new(AlgorithmSelection)
	c.handshakeLog.Algorithms.KexAlgorithm = c.kexAlgorithm

	if c.hostKeyAlgorithm, err = chooseAlgorithm(ckxi.HostKeyAlgorithms, serverKex.HostKeyAlgorithms); err != nil {
		return err
	}
	c.handshakeLog.Algorithms.HostKeyAlgorithm = c.hostKeyAlgorithm
	/*
		if err := c.dhGroup1Kex(); err != nil {
			return err
		}
	*/
	if err := c.dhGroupExchange(); err != nil {
		return err
	}
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
	p.msgType = b[0]
	p.payload = b[1:payloadLength]
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
	switch p.msgType {
	case SSH_MSG_KEXINIT:
		var kxi KeyExchangeInit
		kxi.Unmarshal(p.payload)
		return &kxi, nil
	case SSH_MSG_KEXDH_REPLY:
		var dhir KeyExchangeDHInitReply
		dhir.Unmarshal(p.payload)
		return &dhir, nil
	}
	return nil, errors.New("unimplemented")
}

func (c *Conn) writePacket(payload sshPayload) error {
	payloadBytes, err := payload.Marshal()
	msgType := payload.MsgType()
	if err != nil {
		return err
	}
	if len(payloadBytes) > 32768 {
		return errLongPacket
	}
	paddingLen := 8 - ((4 + 1 + 1 + len(payloadBytes)) % 8)
	if paddingLen < 4 {
		paddingLen += 8
	}
	paddingBytes := make([]byte, paddingLen)
	if len(paddingBytes) > 255 {
		return errInvalidPadding
	}
	pkt := packet{
		packetLength: uint32(2 + len(payloadBytes) + len(paddingBytes)),
		msgType:      msgType,
		payload:      payloadBytes,
		padding:      paddingBytes,
		mac:          []byte{},
	}
	out := make([]byte, 4+1+1+len(pkt.payload)+len(pkt.padding))
	binary.BigEndian.PutUint32(out, pkt.packetLength)
	out[4] = byte(len(pkt.padding))
	out[5] = pkt.msgType
	copy(out[6:], pkt.payload)
	copy(out[6+len(pkt.payload):], pkt.padding)

	written := 0
	for written < len(out) {
		n, err := c.conn.Write(out[written:])
		written += n
		if err != nil {
			return err
		}
	}
	written = 0
	mac := make([]byte, 0)
	for written < len(mac) {
		n, err := c.conn.Write(mac[written:])
		written += n
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) dhGroupExchange() error {
	gexRequest := new(KeyExchangeDHGroupRequest)
	gexRequest.Min = 1024
	gexRequest.Preferred = 2048
	gexRequest.Max = 4096
	if err := c.writePacket(gexRequest); err != nil {
		return err
	}
	return nil
}

func (c *Conn) dhExchange(params *DHParams) error {
	x, err := rand.Int(c.config.getRandom(), params.order)
	if err != nil {
		return err
	}
	dhi := new(KeyExchangeDHInit)
	E := big.NewInt(0)
	E.Exp(params.Generator, x, params.Prime)
	dhi.E.Set(E)
	c.writePacket(dhi)
	rawReply, errRead := c.readPacket()
	if errRead != nil {
		zlog.Debug("waaaaat")
		zlog.Debug(errRead.Error())
		return errRead
	}
	dhReply, ok := rawReply.(*KeyExchangeDHInitReply)
	if !ok {
		return errUnexpectedMessage
	}
	zlog.Debug(rawReply)

	c.handshakeLog.DHReply = dhReply
	return nil
}

func (c *Conn) dhGroup1Kex() error {
	return c.dhExchange(&dhOakleyGroup2)
}

func (c *Conn) dhGroup14Kex() error {
	return c.dhExchange(&dhOakleyGroup14)
}
