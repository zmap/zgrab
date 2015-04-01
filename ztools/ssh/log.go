package ssh

// HandshakeLog contains detailed information about each step of the
// SSH handshake, and can be encoded to JSON.
type HandshakeLog struct {
	ClientProtocol    *ProtocolAgreement `json:"client_protocol,omitempty"`
	ServerProtocol    *ProtocolAgreement `json:"server_protocol,omitempty"`
	ServerKeyExchange *KeyExchangeInit   `json:"server_key_exchange,omitempty"`
}
