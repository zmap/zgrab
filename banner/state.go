package banner

import (
	"../zcrypto/ztls"
)

type StateLog struct {
	StateType string `json:"type"`
	Data interface{} `json:"data"`
	Error error `json:"error"`
}

type ConnectionState interface {
	StateLog() StateLog
}

type readState struct {
	response []byte
	err error
}

type writeState struct {
	toSend []byte
	err error
}

type starttlsState struct {
	response []byte
	err error
}

type tlsState struct {
	handshake ztls.ZtlsHandshakeLog
	err error
}

type heartbleedState struct {
	probe ztls.ZtlsHeartbleedLog
	err error
}

func (rs *readState) Result() {
	return StateLog{
		StateType: "read",
		Data: rs.response,
		Error: rs.err,
	}
}
