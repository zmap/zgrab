package ztls

type ztlsServerHello struct {
	Version 			uint16		`json:"version"`
	Random 				[]byte		`json:"random"`
	SessionId 			[]byte		`json:"session_id"`
	CipherSuite			uint16		`json:"cipher_suite"`
	CompressionMethod 	uint8		`json:"compression_method"`
	NextProtoEnabled	bool		`json:"next_protocol_negotiation"`
	NextProtos			[]string	`json:"next_protocols"`
	OcspStapling		bool		`json:"ocsp_stapling"`
	TicketSupported		bool		`json:"ticket_supported"`
	HeartbeatSupported  bool        `json:"heartbeat_supported"`
}

func (m *serverHelloMsg) ztlsNewServerHello() *ztlsServerHello {
	h := new(ztlsServerHello)
	h.Version = m.vers
	h.Random = m.random
	h.SessionId = m.sessionId
	h.CipherSuite = m.cipherSuite
	h.CompressionMethod = m.compressionMethod
	h.NextProtoEnabled = m.nextProtoNeg
	h.NextProtos = m.nextProtos
	h.OcspStapling = m.ocspStapling
	h.TicketSupported = m.ticketSupported
	h.HeartbeatSupported = m.heartbeatEnabled
	return h
}

type ztlsServerCertificates struct {
	Certificates [][]byte	`json:"certificates"`
	Valid bool `json:"is_valid"`
	ValidationError *string `json:"validation_error"`
	CommonName *string `json:"common_name"`
	AltNames []string `json:"alt_names"`
	Issuer *string `json:"issuer"`
}

func (m *certificateMsg) ztlsNewServerCertificates() *ztlsServerCertificates {
	c := new(ztlsServerCertificates)
	c.Certificates = m.certificates
	c.Valid = m.valid
	c.ValidationError = m.validationError
	if m.commonName != "" {
		c.CommonName = &m.commonName
	}
	c.AltNames = m.altNames
	if m.issuer != "" {
		c.Issuer = &m.issuer
	}
	return c
}

type ztlsServerKeyExchange struct {
	Key	[]byte	`json:"key"`
}

func (m *serverKeyExchangeMsg) ztlsNewServerKeyExchange() *ztlsServerKeyExchange {
	skx := new(ztlsServerKeyExchange)
	skx.Key = m.key
	return skx
}

type ztlsServerFinished struct {
	VerifyData []byte	`json:"verify_data"`
}

func (m *finishedMsg) ztlsNewServerFinished() *ztlsServerFinished {
	fm := new(ztlsServerFinished)
	fm.VerifyData = m.verifyData
	return fm
}

type ZtlsHandshakeLog struct {
	ServerHello 			*ztlsServerHello `json:"server_hello"`
	ServerCertificates 	*ztlsServerCertificates `json:"server_certificates"`
	ServerKeyExchange 	*ztlsServerKeyExchange `json:"server_key_exchange"`
	ServerFinished		*ztlsServerFinished `json:"server_finished"`
}

type ZtlsHeartbleedLog struct {
	Enabled bool `json:"heartbeat_supported"`
	Vulnerable bool `json:"heartbleed_vulnerable"`
}

func (c *Conn) HandshakeLog() *ZtlsHandshakeLog {
	return c.handshakeLog
}

func (c *Conn) HeartbleedLog() *ZtlsHeartbleedLog {
	return c.heartbleedLog
}
