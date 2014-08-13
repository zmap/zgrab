package banner

import (
	"../zcrypto/ztls"
)

type StateLog struct {
	StateType string `json:"type"`
	Data interface{} `json:"data"`
	Error *string `json:"error"`
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
	}
	if cs.err != nil {
		errString := cs.err.Error()
		sl.Error = &errString
	}
	return sl;
}

type readState struct {
	response []byte
	err error
}

func (rs *readState) StateLog() StateLog {
	var data = struct {
		Response string `json:"response"`
	}{
		string(rs.response),
	}
	sl := StateLog {
		StateType: "read",
		Data: data,
	}
	if rs.err != nil {
		errString := rs.err.Error()
		sl.Error = &errString
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
	}
	if ws.err != nil {
		errString := ws.err.Error()
		sl.Error = &errString
	}
	return sl
}

type starttlsState struct {
	response []byte
	err error
}

func (ss *starttlsState) StateLog() StateLog {
	var data = struct {
		Response string `json:"response"`
	}{
		string(ss.response),
	}
	sl := StateLog {
		StateType: "starttls",
		Data: data,
	}
	if ss.err != nil {
		errString := ss.err.Error()
		sl.Error = &errString
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
	}
	if ts.err != nil {
		errString := ts.err.Error()
		sl.Error = &errString
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
	}
	if hs.err != nil {
		errString := hs.err.Error()
		sl.Error = &errString
	}
	return sl
}
