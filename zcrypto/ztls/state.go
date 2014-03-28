package ztls



type ServerHello struct {
	Version 			uint16		`json:"version"`
	Random 				[]byte		`json:"random"`
	SessionId 			[]byte		`json:"session_id"`
	CipherSuite			uint16		`json:"cipher_suite"`
	CompressionMethod 	uint8		`json:"compression_method"`
	NextProtoEnabled	bool		`json:"next_protocol_negotiation"`
	NextProtos			[]string	`json:"next_protocols"`
	OcspStapling		bool		`json:"ocsp_stapling"`
	TicketSupported		bool		`json:"ticket_supported"`
}

func (m *serverHelloMsg) ZtlsNewServerHello() *ServerHello {
	h := new(ServerHello)
	h.Version = m.vers
	h.Random = m.random
	h.SessionId = m.sessionId
	h.CipherSuite = m.cipherSuite
	h.CompressionMethod = m.compressionMethod
	h.NextProtoEnabled = m.nextProtoNeg
	h.NextProtos = m.nextProtos
	h.OcspStapling = m.ocspStapling
	h.TicketSupported = m.ticketSupported
	return h
}

type ServerCertificates struct {
	Certificates [][]byte	`json:"certificates"`
}
func (m *certificateMsg) ZtlsServerCertificates() *ServerCertificates {
	c := new(ServerCertificates)
	c.Certificates = m.certificates
	return c
}

type ServerKeyExchange struct {
	Key	[]byte	`json:"key"`
}

func (m *serverKeyExchangeMsg) ZtlsServerKeyExchange() *ServerKeyExchange {
	skx := new(ServerKeyExchange)
	skx.Key = m.key
	return skx
}

type FinishedMessage struct {
	VerifyData []byte	`json:"verify_data"`
}

func (m *finishedMsg) ZtlsFinishedMessage() *FinishedMessage {
	fm := new(FinishedMessage)
	fm.VerifyData = m.verifyData
	return fm
}



