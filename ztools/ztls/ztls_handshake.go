package ztls

import (
	"errors"

	"github.com/zmap/zgrab/ztools/keys"
	"github.com/zmap/zgrab/ztools/x509"
)

var ErrUnimplementedCipher error = errors.New("unimplemented cipher suite")

type TLSVersion uint16

type ClientHello struct {
	Random    []byte `json:"random"`
	SessionID []byte `json:"session_id,omitempty"`
}

type ServerHello struct {
	Version             TLSVersion  `json:"version"`
	Random              []byte      `json:"random"`
	SessionID           []byte      `json:"session_id"`
	CipherSuite         CipherSuite `json:"cipher_suite"`
	CompressionMethod   uint8       `json:"compression_method"`
	OcspStapling        bool        `json:"ocsp_stapling"`
	TicketSupported     bool        `json:"ticket"`
	SecureRenegotiation bool        `json:"secure_renegotiation"`
	HeartbeatSupported  bool        `json:"heartbeat"`
}

// ServerCertificates represents a TLS certificates message in a format friendly to the golang JSON library.
// ValidationError should be non-nil whenever Valid is false.
type Certificates struct {
	Certificates       [][]byte
	ParsedCertificates []*x509.Certificate
}

// ServerKeyExchange represents the raw key data sent by the server in TLS key exchange message
type ServerKeyExchange struct {
	Raw       []byte             `json:"raw"`
	RSAParams *keys.RSAPublicKey `json:"rsa_params,omitempty"`
	DHParams  *keys.DHParams     `json:"dh_params,omitempty"`
}

// Finished represents a TLS Finished message
type Finished struct {
	VerifyData []byte `json:"verify_data"`
}

// ServerHandshake stores all of the messages sent by the server during a standard TLS Handshake.
// It implements zgrab.EventData interface
type ServerHandshake struct {
	ClientHello        *ClientHello       `json:"client_hello,omitempty"`
	ServerHello        *ServerHello       `json:"server_hello,omitempty"`
	ServerCertificates *Certificates      `json:"server_certificates,omitempty"`
	ServerKeyExchange  *ServerKeyExchange `json:"server_key_exchange,omitempty"`
	ServerFinished     *Finished          `json:"server_finished,omitempty"`
}

func (c *Conn) GetHandshakeLog() *ServerHandshake {
	return c.handshakeLog
}

func (m *clientHelloMsg) MakeLog() *ClientHello {
	ch := new(ClientHello)
	ch.Random = make([]byte, len(m.random))
	copy(ch.Random, m.random)
	ch.SessionID = make([]byte, len(m.sessionId))
	copy(ch.SessionID, m.sessionId)
	return ch
}

func (m *serverHelloMsg) MakeLog() *ServerHello {
	sh := new(ServerHello)
	sh.Version = TLSVersion(m.vers)
	sh.Random = make([]byte, len(m.random))
	copy(sh.Random, m.random)
	sh.SessionID = make([]byte, len(m.sessionId))
	copy(sh.SessionID, m.sessionId)
	sh.CipherSuite = CipherSuite(m.cipherSuite)
	sh.CompressionMethod = m.compressionMethod
	sh.OcspStapling = m.ocspStapling
	sh.TicketSupported = m.ticketSupported
	sh.SecureRenegotiation = m.secureRenegotiation
	sh.HeartbeatSupported = m.heartbeatEnabled
	return sh
}

func (m *certificateMsg) MakeLog() *Certificates {
	sc := new(Certificates)
	sc.Certificates = make([][]byte, len(m.certificates))
	for idx, cert := range m.certificates {
		sc.Certificates[idx] = make([]byte, len(cert))
		copy(sc.Certificates[idx], cert)
	}
	return sc
}

func (m *serverKeyExchangeMsg) MakeLog() *ServerKeyExchange {
	skx := new(ServerKeyExchange)
	skx.Raw = make([]byte, len(m.key))
	copy(skx.Raw, m.key)
	return skx
}

func (m *finishedMsg) MakeLog() *Finished {
	sf := new(Finished)
	sf.VerifyData = make([]byte, len(m.verifyData))
	copy(sf.VerifyData, m.verifyData)
	return sf
}
