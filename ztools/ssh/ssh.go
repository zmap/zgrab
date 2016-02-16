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
	"crypto/rand"
	"errors"
	"io"
	"net"
)

var errShortPacket = errors.New("SSH packet too short")
var errLongPacket = errors.New("SSH packet too long")
var errInvalidPadding = errors.New("Invalid SSH padding")
var errUnexpectedMessage = errors.New("Unexpected SSH message type")
var errShortBuffer = errors.New("Buffer too short")
var errInvalidPlaintextLength = errors.New("Plaintext not a multiple of block size")
var errBadInt = errors.New("Invalid mpint")
var errInvalidProtocolVersion = errors.New("SSH protocol version invalid")

// Client wraps a network connection with an SSH client connection
func Client(c net.Conn, config *Config) *Conn {
	return &Conn{
		conn:   c,
		config: config,
	}
}

// SSH message types. These are usually the first byte of the payload

const (
	SSH_MSG_KEXINIT                byte = 20
	SSH_MSG_KEXDH_INIT             byte = 30
	SSH_MSG_KEXDH_REPLY            byte = 31
	SSH_MSG_KEX_DH_GEX_REQUEST_OLD byte = 30
	SSH_MSG_KEY_DH_GEX_REQUEST     byte = 34
	SSH_MSG_KEX_DH_GEX_GROUP       byte = 31
	SSH_MSG_KEX_DH_GEX_INIT        byte = 32
	SSH_MSG_KEX_DH_GEX_REPLY       byte = 33
)

type Config struct {
	KexAlgorithms             NameList
	HostKeyAlgorithms         NameList
	EncryptionClientToServer  NameList
	EncryptionServerToClient  NameList
	MACClientToServer         NameList
	MACServerToclient         NameList
	CompressionClientToServer NameList
	CompressionServerToClient NameList
	Random                    io.Reader
	KexValue                  []byte
	NegativeOne               bool
}

func (c *Config) getKexAlgorithms() NameList {
	if c.KexAlgorithms != nil {
		return c.KexAlgorithms
	}
	return KnownKexAlgorithmNames
}

func (c *Config) getHostKeyAlgorithms() NameList {
	if c.HostKeyAlgorithms != nil {
		return c.HostKeyAlgorithms
	}
	return KnownHostKeyAlgorithmNames
}

func (c *Config) getClientEncryption() NameList {
	if c.EncryptionClientToServer != nil {
		return c.EncryptionClientToServer
	}
	return KnownEncryptionAlgorithmNames
}

func (c *Config) getServerEncryption() NameList {
	if c.EncryptionServerToClient != nil {
		return c.EncryptionServerToClient
	}
	return c.getClientEncryption()
}

func (c *Config) getClientMAC() NameList {
	if c.MACClientToServer != nil {
		return c.MACClientToServer
	}
	return KnownMACAlgorithmNames
}

func (c *Config) getServerMAC() NameList {
	if c.MACServerToclient != nil {
		return c.MACServerToclient
	}
	return c.getClientMAC()
}

func (c *Config) getClientCompression() NameList {
	if c.CompressionClientToServer != nil {
		return c.CompressionClientToServer
	}
	return KnownCompressionAlgorithmNames
}

func (c *Config) getServerCompression() NameList {
	if c.CompressionServerToClient != nil {
		return c.CompressionServerToClient
	}
	return c.getClientCompression()
}

func (c *Config) getRandom() io.Reader {
	if c.Random != nil {
		return c.Random
	}
	return rand.Reader
}
