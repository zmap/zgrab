package banner

import (
	"log"
	"io"
	"net"
	"time"
	"strings"
	"strconv"
	"crypto/tls"
)

type Result struct {
	Addr string
	Err error
	Data []byte
}

type GrabConfig struct {
	Udp, Tls, SendMessage bool
	Port uint16
	Timeout int
	Message string
	ErrorLog *log.Logger
}

func makeDialer(config *GrabConfig) ( func(rhost string) (net.Conn, error) ) {
	var network string
	if config.Udp {
		network = "udp"
	} else {
		network = "tcp"
	}

	timeout := time.Duration(config.Timeout) * time.Second

	if config.Tls {
		tlsConfig := new(tls.Config)
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.MinVersion = tls.VersionSSL30		
		return func(rhost string) (net.Conn, error) {
			now := time.Now()
			conn, err := net.DialTimeout(network, rhost, timeout)
			if err == nil {
				conn = tls.Client(conn, tlsConfig)
				if config.Timeout != 0 {
					deadline := now.Add(timeout)
					conn.SetDeadline(deadline)
				}
			}
			return conn, err
		}
	} else {
		return func(rhost string) (net.Conn, error) {
			now := time.Now()
			conn, err := net.DialTimeout(network, rhost, timeout)
			if err == nil && config.Timeout != 0 {
				deadline := now.Add(timeout)
				conn.SetDeadline(deadline)
			}
			return conn, err
		}
	}
}

func GrabBanner(addrChan chan net.IP, resultChan chan Result, doneChan chan int, config *GrabConfig) {

	dial := makeDialer(config)
	port := strconv.FormatUint(uint64(config.Port), 10)
	for ip := range addrChan {
		addr := ip.String()
		rhost := net.JoinHostPort(addr, port)
		conn, err := dial(rhost)
		if err != nil {
			config.ErrorLog.Print("Could not connect to host ", addr, " - ", err)
			continue
		}
		if config.SendMessage {
			s := strings.Replace(config.Message, "%s", addr, -1)
			if _, err := conn.Write([]byte(s)); err != nil {
				conn.Close()
				config.ErrorLog.Print("Could not write message to host ", addr, " - ", err)
				continue
			}
		}
		var buf [1024]byte
		n, err := conn.Read(buf[:])
		conn.Close()
		if err != nil && (err != io.EOF || n == 0) {
			res := Result{addr, err, nil}
			resultChan <- res
			continue
		}
		res := Result{addr, nil, buf[0:n]}
		resultChan <- res
	}
	doneChan <- 1
}