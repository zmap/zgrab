package iscsi

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func inner(sn *[4]byte, index int) {
	switch {
	case index < 0:
		return
	case sn[index] == 0xff:
		sn[index] = 0
		index--
		inner(sn, index)
	default:
		sn[index]++
	}
}

func increment(sn *[4]byte) {
	inner(sn, 3)
}

func Scan(conn net.Conn, config *ISCSIConfig) (AuthLog, error) {
	authlog := AuthLog{[]*Target{}, true}
	p := Parameters{[]TextParameter{}, 0}

	p.AddTextParameter("InitiatorName", "iqn.1993-08.org.debian:01:f0f8de6d331")
	p.AddTextParameter("InitiatorAlias", fmt.Sprintf("%0"+fmt.Sprint(len(config.LocalLogin)/4*4+4)+"s", config.LocalLogin))
	p.AddTextParameter("SessionType", "Discovery")
	p.AddTextParameter("HeaderDigest", "None")
	p.AddTextParameter("DataDigest", "None")
	p.AddTextParameter("DefaultTime2Wait", "2")
	p.AddTextParameter("DefaultTime2Retain", "0")
	p.AddTextParameter("IFMarker", "No")
	p.AddTextParameter("OFMarker", "No")
	p.AddTextParameter("ErrorRecoveryLevel", "0")
	p.AddTextParameter("MaxRecvDataSegmentLength", "32768")

	CmdSN := [4]byte{0, 0, 0, 0}

	r := NewLoginRequest(p, CmdSN)
	res, err := r.MarshalBinary()
	if err != nil {
		return authlog, err
	}

	_, err = conn.Write(res)
	if err != nil {
		return authlog, err
	}

	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		return authlog, err
	}

	response := NewLoginResponse()
	err = response.UnmarshalBinary(buf)
	if err != nil && err != io.EOF {
		return authlog, err
	}
	if response.Header.(*LoginResponseHeader).Opcode != LOGIN_RESPONSE {
		return authlog, errors.New("iSCSI-login failed")
	}

	increment(&CmdSN)

	p = Parameters{[]TextParameter{}, 0}
	p.AddTextParameter("SendTargets", "All")
	r2 := NewTextRequest(p, CmdSN, CmdSN)
	res, err = r2.MarshalBinary()
	if err != nil {
		return authlog, err
	}

	_, err = conn.Write(res)
	if err != nil {
		return authlog, err
	}

	buf = make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		return authlog, err
	}
	response2 := NewTextResponse()
	err = response2.UnmarshalBinary(buf)
	if err != nil && err != io.EOF {
		return authlog, err
	}

	if response2.Header.(*TextResponseHeader).Opcode != TEXT_RESPONSE {
		return authlog, errors.New("No text response")
	}

	targets := map[string]string{}
	tl := response2.Data.Data
	for i := 0; i < len(tl); i += 2 {
		if i+1 >= len(tl) {
			targets[tl[i].Value] = "N/A"
		} else {
			targets[tl[i].Value] = tl[i+1].Value
		}
	}

	for target, ip := range targets {
		t := Target{target, ip, false, true}
		authlog.Targets = append(authlog.Targets, &t)

		// 3 second connection establish timeout
		conn2, err := net.DialTimeout("tcp", conn.RemoteAddr().String(), time.Second*3)
		if err != nil {
			continue
		}
		// 3 second read/write timeouts
		conn2.SetDeadline(time.Now().Add(time.Second * 3))
		defer conn2.Close()

		p := Parameters{[]TextParameter{}, 0}
		p.AddTextParameter("InitiatorName", "iqn.1993-08.org.debian:01:f0f8de6d331")
		//p.AddTextParameter("InitiatorName", "iqn.1994-05.com.redhat:4fd2932635a0")
		p.AddTextParameter("InitiatorAlias", fmt.Sprintf("%0"+fmt.Sprint(len(config.LocalLogin)/4*4+4)+"s", config.LocalLogin))
		p.AddTextParameter("TargetName", target)
		p.AddTextParameter("SessionType", "Normal")
		p.AddTextParameter("HeaderDigest", "None")
		p.AddTextParameter("DataDigest", "None")
		p.AddTextParameter("DefaultTime2Wait", "2")
		p.AddTextParameter("DefaultTime2Retain", "0")
		p.AddTextParameter("IFMarker", "No")
		p.AddTextParameter("OFMarker", "No")
		p.AddTextParameter("ErrorRecoveryLevel", "0")
		p.AddTextParameter("InitialR2T", "No")
		p.AddTextParameter("ImmediateData", "Yes")
		p.AddTextParameter("MaxBurstLength", "16776192")
		p.AddTextParameter("FirstBurstLength", "262144")
		p.AddTextParameter("MaxOutstandingR2T", "1")
		p.AddTextParameter("MaxConnections", "1")
		p.AddTextParameter("DataPDUInOrder", "Yes")
		p.AddTextParameter("DataSequenceInOrder", "Yes")
		p.AddTextParameter("MaxRecvDataSegmentLength", "262144")
		r = NewLoginRequest(p, CmdSN)
		res, err = r.MarshalBinary()
		if err != nil {
			continue
		}

		_, err = conn2.Write(res)
		if err != nil {
			continue

		}

		buf = make([]byte, 1024)
		_, err = conn2.Read(buf)
		if err != nil {
			continue
		}
		response = NewLoginResponse()
		err = response.UnmarshalBinary(buf)
		if err != nil && err != io.EOF {
			continue
		}

		t.HadError = response.Header.(*LoginResponseHeader).Opcode != LOGIN_RESPONSE

		if response.Header.(*LoginResponseHeader).StatusClass == 0 && response.Header.(*LoginResponseHeader).StatusDetail == 0 {
			t.AuthDisabled = true
		}

	}
	authlog.HadError = false
	for _, target := range authlog.Targets {
		if target.HadError {
			authlog.HadError = true
			break
		}
	}
	return authlog, nil
}
