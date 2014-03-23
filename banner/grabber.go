package banner

import (
	"fmt"
	"os"
	"net"
	"strings"
	"crypto/tls"
)

type Result struct {
	Addr string
	Err error
	Data []byte
}

func GrabBanner(addrChan chan net.IP, resultChan chan Result) {
	for ip := range addrChan {
		addr := ip.String()
		rhost := net.JoinHostPort(addr, "443")
		var tlsConfig tls.Config
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.MinVersion = tls.VersionSSL30
		conn, err := tls.Dial("tcp", rhost, &tlsConfig)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Could not connect to host: ", ip, err)
			continue
		}
		message := "GET / HTTP/1.1\nHost: %s\n\n\n"
		s := strings.Replace(message, "%s", addr, -1)
		if _, err := conn.Write([]byte(s)); err != nil {
			conn.Close()
			fmt.Fprintln(os.Stderr, "Could not write message to host: ", s)
			continue
		}
		var buf [1024]byte
		n, err := conn.Read(buf[:])
		conn.Close()
		//if err != nil && (err != io.EOF || n == 0) {
		//}
		res := Result{addr, err, buf[0:n]}
		resultChan <- res
	}
	close(resultChan)
}