package banner

import (
	"log"
	"net"
	"time"
	"strconv"
)

type GrabConfig struct {
	Tls bool
	Banners bool
	SendMessage bool
	ReadResponse bool
	StartTls bool
	Heartbleed bool
	Port uint16
	Timeout int
	Message []byte
	Protocol string
	ErrorLog *log.Logger
	LocalAddr net.Addr
}

type Grab struct {
	Host string
	Port uint16
	Time time.Time
	Log []StateLog
}

type Progress struct {

}

func makeDialer(c *GrabConfig) (func(string) (*Conn, error)) {
	proto := c.Protocol
	deadline := time.Duration(c.Timeout)*time.Second
	return func(addr string) (*Conn, error) {
		d := Dialer {
			Deadline: time.Now().Add(deadline),
		}
		return d.Dial(proto, addr)
	}
}

func makeGrabber(config *GrabConfig) (func(*Conn) []StateLog) {
	banner := make([]byte, 1024)
	response := make([]byte, 65536)
	// Do all the hard work here
	g := func(c *Conn) error {
		if config.Tls {
			if err := c.TlsHandshake(); err != nil {
				return err
			}
		}
		if config.Banners {
			if _, err := c.Read(banner); err != nil {
				return err
			}
		}
		if config.SendMessage {
			if _, err := c.Write(config.Message); err != nil {
				return err
			}
		}
		if config.ReadResponse {
			if _, err := c.Read(response); err != nil {
				return err
			}
		}
		if config.StartTls {
			if err := c.StarttlsHandshake(); err != nil {
				return err
			}
		}
		if config.Heartbleed {
			buf := make([]byte, 256)
			if _, err := c.SendHeartbleedProbe(buf); err != nil {
				return err
			}
		}
		return nil
	}
	// Wrap the whole thing in a logger
	return func(c *Conn) []StateLog {
		err := g(c);
		if err != nil {
			config.ErrorLog.Printf("Conversation error with remote host %s: %s",
				c.RemoteAddr().String(), err.Error())
		}
		return c.States()
	}
}

func GrabBanner(addrChan chan net.IP, grabChan chan Grab, doneChan chan Progress, config *GrabConfig) {
	dial := makeDialer(config)
	grabber := makeGrabber(config)
	port := strconv.FormatUint(uint64(config.Port), 10)
	for ip := range addrChan {
		addr := ip.String()
		rhost := net.JoinHostPort(addr, port)
		startTime := time.Now()
		conn, dialErr := dial(rhost)
		if dialErr != nil {
			// Could not connect to host
			config.ErrorLog.Printf("Could not connect to remote host %s: %s",
				addr, dialErr.Error())
			grabChan <- Grab{addr, config.Port, startTime, conn.States()}
			continue
		}
		grabStates := grabber(conn)
		grabChan <- Grab{addr, config.Port, startTime, grabStates}
	}
	doneChan <- Progress{}
}
