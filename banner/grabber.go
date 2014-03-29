package banner

import (
	"log"
	"io"
	"net"
	"time"
	"strings"
	"strconv"
	"../zcrypto/ztls"
)

type Result struct {
	Addr string
	Err error
	TlsHandshakeLog TlsLog
	Data []byte
}

type GrabConfig struct {
	Udp, Tls, SendMessage bool
	Port uint16
	Timeout int
	Message string
	ErrorLog *log.Logger
	LocalAddr net.Addr
}

func makeDialer(config *GrabConfig) ( func(rhost string) (net.Conn, TlsLog, error) ) {
	var network string
	if config.Udp {
		network = "udp"
	} else {
		network = "tcp"
	}

	timeout := time.Duration(config.Timeout) * time.Second

	if config.Tls {
		tlsConfig := new(ztls.Config)
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.MinVersion = ztls.VersionSSL30		
		return func(rhost string) (net.Conn, TlsLog, error) {
			now := time.Now()
			deadline := now.Add(timeout)
			dialer := net.Dialer{timeout, deadline, config.LocalAddr, false}
			var conn *ztls.Conn
			if nconn, err := dialer.Dial(network, rhost); err != nil {
				return nconn, nil, err
			} else {
				conn = ztls.Client(nconn, tlsConfig)
				conn.SetDeadline(deadline)
				err = conn.Handshake()
				return conn, conn.ConnectionLog(), err
			}
		}
	} else {
		return func(rhost string) (net.Conn, TlsLog, error) {
			now := time.Now()
			dialer := net.Dialer{timeout, now.Add(timeout), config.LocalAddr, false}
			conn, err := dialer.Dial(network, rhost)
			return conn, nil, err
		}
	}
}

func GrabBanner(addrChan chan net.IP, resultChan chan Result, doneChan chan int, config *GrabConfig) {
	dial := makeDialer(config)
	port := strconv.FormatUint(uint64(config.Port), 10)
	for ip := range addrChan {
		addr := ip.String()
		rhost := net.JoinHostPort(addr, port)
		conn, tlsLog, err := dial(rhost)
		if err != nil {
			config.ErrorLog.Print("Could not connect to host ", addr, " - ", err)
			resultChan <- Result{addr, err, tlsLog, nil}
			continue
		}
		if config.SendMessage {
			s := strings.Replace(config.Message, "%s", addr, -1)
			if _, err := conn.Write([]byte(s)); err != nil {
				conn.Close()
				config.ErrorLog.Print("Could not write message to host ", addr, " - ", err)
				resultChan <- Result{addr, err, tlsLog, nil}
				continue
			}
		}
		var buf [1024]byte
		n, err := conn.Read(buf[:])
		conn.Close()
		if err != nil && (err != io.EOF || n == 0) {
			config.ErrorLog.Print("Could not read from host ", addr, " - ", err)
			res := Result{addr, err, tlsLog, nil}
			resultChan <- res
			continue
		}
		res := Result{addr, nil, tlsLog, buf[0:n]}
		resultChan <- res
	}
	doneChan <- 1
}