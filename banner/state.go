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
	res := string(rs.response)
	var rptr *string
	if len(res) > 0 {
		rptr = &res
	} else {
		rptr = nil
	}
	var data = struct {
		Response *string `json:"response"`
	}{
		rptr,
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
	sent := string(ws.toSend)
	var sent_ptr *string
	if sent == "" {
		sent_ptr = nil
	} else {
		sent_ptr = &sent
	}
	var data = struct {
		Sent *string `json:"sent"`
	}{
		sent_ptr,
	}
	sl := StateLog {
		StateType: "write",
		Data: data,
	}
	if ws.err != nil {
		errString := ws.err.Error()
		sl.Error = &errString
	}
	return sl
}

type ehloState struct {
	response []byte
	err error
}

func (es *ehloState) StateLog() StateLog {
	res := string(es.response)
	var res_ptr *string
	if res == "" {
		res_ptr = nil
	} else {
		res_ptr = &res
	}
	var data = struct {
		Response *string `json:"response"`
	}{
		res_ptr,
	}
	sl := StateLog {
		StateType: "ehlo",
		Data: data,
	}
	if es.err != nil {
		errString := es.err.Error()
		sl.Error = &errString
	}
	return sl
}

type helpState struct {
	response []byte
	err error
}

func (hs *helpState) StateLog() StateLog {
	res := string(hs.response)
	var res_ptr *string
	if res == "" {
		res_ptr = nil
	} else {
		res_ptr = &res
	}
	var data = struct {
		Response *string `json:"response"`
	}{
		res_ptr,
	}
	sl := StateLog {
		StateType: "smtp-help",
		Data: data,
	}
	if hs.err != nil {
		errString := hs.err.Error()
		sl.Error = &errString
	}
	return sl
}

type starttlsState struct {
	command []byte
	response []byte
	err error
}

func (ss *starttlsState) StateLog() StateLog {
	res := string(ss.response)
	var res_ptr *string
	if res == "" {
		res_ptr = nil
	} else {
		res_ptr = &res
	}
	var data = struct {
		Command string `json:"command"`
		Response *string `json:"response"`
	}{
		string(ss.command),
		res_ptr,
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
