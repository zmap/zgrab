package ztls

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/zmap/zgrab/ztools/keys"
	"github.com/zmap/zgrab/ztools/x509"
)

var ErrUnimplementedCipher error = errors.New("unimplemented cipher suite")

type TLSVersion uint16

type CipherSuite uint16

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

// Certificates represents a TLS certificates message in a format friendly to the golang JSON library.
// ValidationError should be non-nil whenever Valid is false.
type Certificates struct {
	Certificates       [][]byte
	ParsedCertificates []*x509.Certificate
}

// ServerKeyExchange represents the raw key data sent by the server in TLS key exchange message
type ServerKeyExchange struct {
	Raw            []byte             `json:"-"`
	RSAParams      *keys.RSAPublicKey `json:"rsa_params,omitempty"`
	DHParams       *keys.DHParams     `json:"dh_params,omitempty"`
	Signature      *DigitalSignature  `json:"signature,omitempty"`
	SignatureError string             `json:"signature_error,omitempty"`
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

// MarshalJSON implements the json.Marshler interface
func (v *TLSVersion) MarshalJSON() ([]byte, error) {
	aux := struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{
		Name:  v.String(),
		Value: int(*v),
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (v *TLSVersion) UnmarshalJSON(b []byte) error {
	aux := struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*v = TLSVersion(aux.Value)
	if expectedName := v.String(); expectedName != aux.Name {
		return fmt.Errorf("mismatched tls version and name: version: %d, name: %s, expected name: %s", aux.Value, aux.Name, expectedName)
	}
	return nil
}

// MarshalJSON implements the json.Marshler interface
func (cs *CipherSuite) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = byte(*cs >> 8)
	buf[1] = byte(*cs)
	enc := strings.ToUpper(hex.EncodeToString(buf))
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{
		Hex:   fmt.Sprintf("0x%s", enc),
		Name:  cs.String(),
		Value: int(*cs),
	}
	return json.Marshal(&aux)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (cs *CipherSuite) UnmarshalJSON(b []byte) error {
	aux := struct {
		Hex   string `json:"hex"`
		Name  string `json:"name"`
		Value uint16 `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if expectedName := nameForSuite(aux.Value); expectedName != aux.Name {
		return fmt.Errorf("mismatched cipher suite and name, suite: %d, name: %s, expected name: %s", aux.Value, aux.Name, expectedName)
	}
	*cs = CipherSuite(aux.Value)
	return nil
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

func (m *serverKeyExchangeMsg) MakeLog(ka keyAgreement) *ServerKeyExchange {
	skx := new(ServerKeyExchange)
	skx.Raw = make([]byte, len(m.key))
	var auth keyAgreementAuthentication
	var errAuth error
	copy(skx.Raw, m.key)

	// Write out parameters
	switch ka := ka.(type) {
	case *rsaKeyAgreement:
		skx.RSAParams = ka.RSAParams()
		errAuth = ka.verifyError
	case *dheKeyAgreement:
		skx.DHParams = ka.DHParams()
		auth = ka.auth
		errAuth = ka.verifyError
	case *ecdheKeyAgreement:
		auth = ka.auth
		errAuth = ka.verifyError
	default:
		break
	}

	// Write out signature
	switch auth := auth.(type) {
	case *signedKeyAgreement:
		skx.Signature = auth.Signature()
	default:
		break
	}

	// Write the signature validation error
	if errAuth != nil {
		skx.SignatureError = errAuth.Error()
	}

	return skx
}

func (m *finishedMsg) MakeLog() *Finished {
	sf := new(Finished)
	sf.VerifyData = make([]byte, len(m.verifyData))
	copy(sf.VerifyData, m.verifyData)
	return sf
}
