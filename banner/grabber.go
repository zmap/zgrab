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
	FirstData []byte
	Err error
	TlsHandshakeLog TlsLog
	Data []byte
}

type GrabConfig struct {
	Udp, Tls, SendMessage, StartTls, ReadFirst, Heartbleed bool
	Port uint16
	Timeout int
	Message string
	ErrorLog *log.Logger
	LocalAddr net.Addr
}

func makeDialer(config *GrabConfig) ( func(rhost string) (net.Conn, []byte, TlsLog, error) ) {
	var network string
	if config.Udp {
		network = "udp"
	} else {
		network = "tcp"
	}

	timeout := time.Duration(config.Timeout) * time.Second

	b := make([]byte, 65536)
	if config.Tls {
		tlsConfig := new(ztls.Config)
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.MinVersion = ztls.VersionSSL30
		return func(rhost string) (net.Conn, []byte, TlsLog, error) {
			now := time.Now()
			deadline := now.Add(timeout)
			dialer := net.Dialer{Timeout:timeout, Deadline:deadline, LocalAddr:config.LocalAddr, DualStack:false}
			var conn *ztls.Conn
			firstRead := []byte{}
			if nconn, err := dialer.Dial(network, rhost); err != nil {
				return nconn, firstRead, nil, err
			} else {
				nconn.SetDeadline(deadline)
				if config.ReadFirst {
					res := make([]byte, 1024)
					// TODO add logging
					if firstReadBytes, err := nconn.Read(res); err != nil {
						log.Print("failed first read")
						return nconn, firstRead, nil, err
					} else {
						firstRead = make([]byte, firstReadBytes)
						copy(firstRead, res)
					}
				}
				if config.StartTls {
					res := make([]byte, 1024)
					if _, err := nconn.Write([]byte("EHLO eecs.umich.edu\r\n")); err != nil {
						log.Print("failed EHLO")
						return nconn, firstRead, nil, err
					}
					if _, err := nconn.Read(res); err != nil {
						// TODO Validate server likes it
						log.Print("failed EHLO read")
					}
					if _, err := nconn.Write([]byte("STARTTLS\r\n")); err != nil {
						log.Print("failed starttls");
					}
					if _, err := nconn.Read(res); err != nil {
						log.Print("failed starttls read")
					}
				}
				conn = ztls.Client(nconn, tlsConfig)
				conn.SetDeadline(deadline)
				err = conn.Handshake()
				if err == nil && config.Heartbleed {
					conn.CheckHeartbleed(b)
				}
				return conn, firstRead, conn.ConnectionLog(), err
			}
		}
	} else {
		return func(rhost string) (net.Conn, []byte, TlsLog, error) {
			now := time.Now()
			deadline := now.Add(timeout)
			dialer := net.Dialer{Timeout:timeout, Deadline:deadline, LocalAddr:config.LocalAddr}
			conn, err := dialer.Dial(network, rhost);
			if err == nil {
				conn.SetDeadline(deadline)
			}
			return conn, []byte{}, nil, err
		}
	}
}

func GrabBanner(addrChan chan net.IP, resultChan chan Result, doneChan chan int, config *GrabConfig) {
	dial := makeDialer(config)
	port := strconv.FormatUint(uint64(config.Port), 10)
	for ip := range addrChan {
		addr := ip.String()
		rhost := net.JoinHostPort(addr, port)
		conn, firstData, tlsLog, err := dial(rhost)
		if err != nil {
			config.ErrorLog.Print("Could not connect to host ", addr, " - ", err)
			resultChan <- Result{addr, firstData, err, tlsLog, nil}
			continue
		}
		if config.SendMessage {
			s := strings.Replace(config.Message, "%s", addr, -1)
			if _, err := conn.Write([]byte(s)); err != nil {
				conn.Close()
				config.ErrorLog.Print("Could not write message to host ", addr, " - ", err)
				resultChan <- Result{addr, firstData, err, tlsLog, nil}
				continue
			}
		}
		var buf [1024]byte
		n, err := conn.Read(buf[:])
		conn.Close()
		if err != nil && (err != io.EOF || n == 0) {
			config.ErrorLog.Print("Could not read from host ", addr, " - ", err)
			res := Result{addr, firstData, err, tlsLog, nil}
			resultChan <- res
			continue
		}
		res := Result{addr, firstData, nil, tlsLog, buf[0:n]}
		resultChan <- res
	}
	doneChan <- 1
}
