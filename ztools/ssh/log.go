package ssh

// HandshakeLog contains detailed information about each step of the
// SSH handshake, and can be encoded to JSON.
type HandshakeLog struct {
	ClientProtocol        *ProtocolAgreement      `json:"client_protocol,omitempty"`
	ServerProtocol        *ProtocolAgreement      `json:"server_protocol,omitempty"`
	ClientKexExchangeInit *KeyExchangeInit        `json:"client_key_exchange_init,omitempty"`
	ServerKeyExchangeInit *KeyExchangeInit        `json:"server_key_exchange_init,omitempty"`
	KexAlgorithm          string                  `json:"chosen_kex_algorithm,omitempty"`
	DHInit                *KeyExchangeDHInit      `json:"key_exchange_dh_init,omitempty"`
	DHReply               *KeyExchangeDHInitReply `json:"key_exchange_dh_reply,omitempty"`
}
