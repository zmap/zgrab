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
	Timeout time.Duration
	Message []byte
	Protocol string
	ErrorLog *log.Logger
	LocalAddr net.Addr
}

type Grab struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	Time time.Time `json:"timestamp"`
	Log []StateLog `json:"log"`
}

type Progress struct {
	Success uint
	Error uint
	Total uint
}

func makeDialer(c *GrabConfig) (func(string) (*Conn, error)) {
	proto := c.Protocol
	timeout := c.Timeout
	return func(addr string) (*Conn, error) {
		deadline := time.Now().Add(timeout)
		d := Dialer {
			Deadline: deadline,
		}
		conn, err := d.Dial(proto, addr)
		if err == nil {
			conn.SetDeadline(deadline)
		}
		return conn, err
	}
}

func makeGrabber(config *GrabConfig) (func(*Conn) ([]StateLog, error)) {
	// Do all the hard work here
	g := func(c *Conn) error {
		banner := make([]byte, 1024)
		response := make([]byte, 65536)
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
	return func(c *Conn) ([]StateLog, error) {
		err := g(c);
		if err != nil {
			config.ErrorLog.Printf("Conversation error with remote host %s: %s",
				c.RemoteAddr().String(), err.Error())
		}
		return c.States(), err
	}
}

func GrabBanner(addrChan chan net.IP, grabChan chan Grab, doneChan chan Progress, config *GrabConfig) {
	dial := makeDialer(config)
	grabber := makeGrabber(config)
	port := strconv.FormatUint(uint64(config.Port), 10)
	p := Progress{}
	for ip := range addrChan {
		p.Total += 1
		addr := ip.String()
		rhost := net.JoinHostPort(addr, port)
		t := time.Now()
		conn, dialErr := dial(rhost)
		if dialErr != nil {
			// Could not connect to host
			config.ErrorLog.Printf("Could not connect to remote host %s: %s",
				addr, dialErr.Error())
			grabChan <- Grab{addr, config.Port, t, conn.States()}
			p.Error += 1
			continue
		}
		grabStates, err := grabber(conn)
		if err != nil {
			p.Error += 1
		} else {
			p.Success += 1
		}
		grabChan <- Grab{addr, config.Port, t, grabStates}
	}
	doneChan <- p
}
