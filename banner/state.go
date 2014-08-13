package banner

import (
	"../zcrypto/ztls"
)

type StateLog struct {
	StateType string `json:"type"`
	Data interface{} `json:"data"`
	Error error `json:"error"`
}

type ConnectionOperation interface {
	StateLog() StateLog
}

type connectState struct {
	protocol string
	remoteHost string
	err error
}

func (cs *connectState) StateLog() StateLog {
	sl := StateLog {
		StateType: "connect",
		Data: nil,
		Error: cs.err,
	}
	return sl;
}

type readState struct {
	response []byte
	err error
}

func (rs *readState) StateLog() StateLog {
	var data = struct {
		response string `json:"response"`
	}{
		string(rs.response),
	}
	sl := StateLog {
		StateType: "read",
		Data: data,
		Error: rs.err,
	}
	return sl
}

type writeState struct {
	toSend []byte
	err error
}

func (ws *writeState) StateLog() StateLog {
	sl := StateLog {
		StateType: "write",
		Data: nil,
		Error: ws.err,
	}
	return sl
}

type starttlsState struct {
	response []byte
	err error
}

func (ss *starttlsState) StateLog() StateLog {
	var data = struct {
		response string `json:"response"`
	}{
		string(ss.response),
	}
	sl := StateLog {
		StateType: "starttls",
		Data: data,
		Error: ss.err,
	}
	return sl
}

type tlsState struct {
	handshake *ztls.ZtlsHandshakeLog
	err error
}

func (ts *tlsState) StateLog() StateLog {
	sl := StateLog {
		StateType: "tls_handshake",
		Data: ts.handshake,
		Error: ts.err,
	}
	return sl
}

type heartbleedState struct {
	probe *ztls.ZtlsHeartbleedLog
	err error
}

func (hs *heartbleedState) StateLog() StateLog {
	sl := StateLog {
		StateType: "heartbleed",
		Data: hs.probe,
		Error: hs.err,
	}
	return sl
}
