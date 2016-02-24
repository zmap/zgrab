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

package ssh

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"regexp"
	"strconv"
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

	dropbearCompatMode bool
}

type sshPayload interface {
	MsgType() byte
	Marshal() ([]byte, error)
	Unmarshal([]byte) bool
}

var dropbearRegex = regexp.MustCompile(`^dropbear_([\d]+)\.([\d]+)`)

const (
	maxProtoSize = 256 * 8
)

func (c *Conn) ClientHandshake() error {
	clientProtocol := MakeZGrabProtocolAgreement()
	clientProtocolBytes := clientProtocol.Marshal()
	c.conn.Write(clientProtocolBytes)

	buf := make([]byte, maxProtoSize)
	protocolDone := false
	protocolRead := 0
	lineStart := 0
	lineEnd := 0

ProtocolLoop:
	for !protocolDone && protocolRead < maxProtoSize {

		// Read one "line"
		lineDone := false
		cur := lineStart
		for !lineDone && protocolRead < maxProtoSize {
			n, err := c.conn.Read(buf[cur : cur+1])
			cur += n
			protocolRead += n
			if err != nil {
				break ProtocolLoop
			}
			if cur-lineStart < 2 {
				continue
			}
			if buf[cur-1] == byte('\n') {
				lineDone = true
				lineEnd = cur
			}
		}

		// Check if it's the version banner
		line := buf[lineStart:lineEnd]
		lineStart = lineEnd
		if len(line) < 5 {
			continue
		}
		if !bytes.Equal(line[0:3], []byte("SSH")) {
			continue
		}
		protocolDone = true
	}
	serverProtocol := ProtocolAgreement{
		RawBanner: string(buf[0:protocolRead]),
	}
	serverProtocol.ParseRawBanner()
	c.handshakeLog.ServerProtocol = &serverProtocol
	if !protocolDone {
		return errInvalidProtocolVersion
	}

	serverSoftware := serverProtocol.SoftwareVersion
	if matches := dropbearRegex.FindStringSubmatch(serverSoftware); len(matches) == 3 {
		major, errMajor := strconv.Atoi(matches[1])
		minor, errMinor := strconv.Atoi(matches[2])
		if errMajor == nil && errMinor == nil && major == 0 && minor <= 46 {
			c.dropbearCompatMode = true
		}
	}

	// See if it matches????

	// Read the key options
	serverKex := new(KeyExchangeInit)
	err := c.readPacket(serverKex)
	if err != nil {
		return err
	}

	c.handshakeLog.ServerKeyExchangeInit = serverKex

	//
	ckxi, err := GenerateKeyExchangeInit(c.config)
	if err != nil {
		return err
	}
	if c.dropbearCompatMode {
		if len(c.config.HostKeyAlgorithms) == 0 {
			ckxi.KexAlgorithms = dropbear_0_46.kexAlgorithms
		}
		ckxi.HostKeyAlgorithms = dropbear_0_46.hostKeyAlgorithms
		ckxi.EncryptionClientToServer = dropbear_0_46.encryptionAlgorithms
		ckxi.EncryptionServerToClient = dropbear_0_46.encryptionAlgorithms
		ckxi.MACClientToServer = dropbear_0_46.macAlgorithms
		ckxi.MACClientToServer = dropbear_0_46.macAlgorithms
	}
	if err = c.writePacket(ckxi); err != nil {
		return err
	}

	if c.kexAlgorithm, err = chooseAlgorithm(ckxi.KexAlgorithms, serverKex.KexAlgorithms); err != nil {
		return err
	}

	c.handshakeLog.Algorithms = new(AlgorithmSelection)
	c.handshakeLog.Algorithms.KexAlgorithm = c.kexAlgorithm

	if c.hostKeyAlgorithm, err = chooseAlgorithm(ckxi.HostKeyAlgorithms, serverKex.HostKeyAlgorithms); err != nil {
		return err
	}
	c.handshakeLog.Algorithms.HostKeyAlgorithm = c.hostKeyAlgorithm

	switch c.kexAlgorithm {
	case KEX_DH_GROUP1_SHA1:
		if err := c.dhGroup1Kex(); err != nil {
			return err
		}
	case KEX_DH_GROUP14_SHA1:
		if err := c.dhGroup14Kex(); err != nil {
			return err
		}
	case KEX_DH_SHA1, KEX_DH_SHA256:
		if err := c.dhGroupExchange(); err != nil {
			return err
		}
	default:
		return errors.New("unimplemented kex method")
	}
	return nil
}

func (c *Conn) HandshakeLog() *HandshakeLog {
	return &c.handshakeLog
}

func (c *Conn) readPacket(expected sshPayload) error {
	// Make a buffer of max packet size
	buf := make([]byte, 35001)
	totalRead, err := c.conn.Read(buf[0:4])
	if err != nil {
		return err
	}
	for totalRead < 4 {
		n, err := c.conn.Read(buf[totalRead:4])
		totalRead += n
		if err != nil {
			return err
		}
	}
	var p packet
	p.packetLength = binary.BigEndian.Uint32(buf[0:4])
	if p.packetLength > 35000 {
		return errLongPacket
	}
	totalLength := expectedLength(p.packetLength, c.macLength)
	for totalRead < totalLength {
		n, err := c.conn.Read(buf[totalRead:totalLength])
		totalRead += n
		if err != nil {
			return err
		}
	}
	// Fill out the rest of the packet
	b := buf[4:totalLength]

	// Read padding length
	if len(b) < 1 {
		return errShortPacket
	}
	p.paddingLength = b[0]
	b = b[1:]
	if uint32(p.paddingLength) > p.packetLength-1 {
		return errInvalidPadding
	}

	// Read the payload
	payloadLength := p.packetLength - uint32(p.paddingLength) - 1
	p.msgType = b[0]
	p.payload = b[1:payloadLength]
	b = b[payloadLength:]

	// Read the padding
	p.padding = b[0:p.paddingLength]
	b = b[p.paddingLength:]

	// Read the MAC, if applicable
	if uint32(len(b)) != c.macLength {
		return errShortPacket
	}

	if c.macLength > 0 {
		p.mac = b[0:c.macLength]
	}
	if len(p.payload) < 1 {
		return errShortPacket
	}
	if p.msgType != expected.MsgType() {
		return errUnexpectedMessage
	}
	if ok := expected.Unmarshal(p.payload); !ok {
		return errors.New("could not unmarshal")
	}

	return nil
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
	gexRequest.Preferred = 3072
	gexRequest.Max = 8192
	if err := c.writePacket(gexRequest); err != nil {
		return err
	}
	gexParams := new(KeyExchangeDHGroupParameters)
	if err := c.readPacket(gexParams); err != nil {
		return err
	}
	c.handshakeLog.KexDHGroupParams = gexParams

	gexInit := new(KeyExchangeDHGroupInit)
	g := big.NewInt(0).SetBytes(gexParams.Generator.Bytes())
	p := big.NewInt(0).SetBytes(gexParams.Prime.Bytes())
	order := big.NewInt(0)
	order.Sub(p, big.NewInt(1))
	if len(c.config.KexValue) > 0 {
		gexInit.E.SetBytes(c.config.KexValue)
	} else if c.config.NegativeOne {
		one := big.NewInt(1)
		gexInit.E.Sub(p, one)
	} else {
		x, err := rand.Int(c.config.getRandom(), order)
		if err != nil {
			return err
		}
		gexInit.E.Exp(g, x, p)
	}
	if err := c.writePacket(gexInit); err != nil {
		return err
	}
	gexReply := new(KeyExchangeDHGroupReply)
	if err := c.readPacket(gexReply); err != nil {
		return err
	}
	c.handshakeLog.KexDHGroupReply = gexReply
	return nil
}

func (c *Conn) dhExchange(params *DHParams) error {
	dhi := new(KeyExchangeDHInit)
	if len(c.config.KexValue) > 0 {
		dhi.E.SetBytes(c.config.KexValue)
	} else if c.config.NegativeOne {
		one := big.NewInt(1)
		dhi.E.Sub(params.Prime, one)
	} else {
		x, err := rand.Int(c.config.getRandom(), params.order)
		if err != nil {
			return err
		}
		E := big.NewInt(0)
		E.Exp(params.Generator, x, params.Prime)
		dhi.E.Set(E)
	}
	c.writePacket(dhi)
	dhReply := new(KeyExchangeDHInitReply)
	if err := c.readPacket(dhReply); err != nil {
		return err
	}

	c.handshakeLog.DHReply = dhReply
	return nil
}

func (c *Conn) dhGroup1Kex() error {
	return c.dhExchange(&dhOakleyGroup2)
}

func (c *Conn) dhGroup14Kex() error {
	return c.dhExchange(&dhOakleyGroup14)
}
