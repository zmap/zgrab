package zlib

import (
	"bytes"
	"net"
	"strconv"
	"time"
)

type GrabTarget struct {
	Addr   net.IP
	Domain string
}

func makeDialer(c *Config) func(string) (*Conn, error) {
	proto := "tcp"
	timeout := c.Timeout
	return func(addr string) (*Conn, error) {
		deadline := time.Now().Add(timeout)
		d := Dialer{
			Deadline: deadline,
		}
		conn, err := d.Dial(proto, addr)
		conn.maxTlsVersion = c.TLSVersion
		if err == nil {
			conn.SetDeadline(deadline)
		}
		return conn, err
	}
}

func makeGrabber(config *Config) func(*Conn) ([]ConnectionEvent, error) {
	// Do all the hard work here
	g := func(c *Conn) error {
		banner := make([]byte, 1024)
		response := make([]byte, 65536)
		c.SetCAPool(config.RootCAPool)
		if config.CBCOnly {
			c.SetCbcOnly()
		}
		if config.TLS {
			if err := c.TLSHandshake(); err != nil {
				return err
			}
		}
		if config.Banners {
			if config.SMTP {
				if _, err := c.SMTPBanner(banner); err != nil {
					return err
				}
			} else if config.POP3 {
				if _, err := c.POP3Banner(banner); err != nil {
					return err
				}
			} else if config.IMAP {
				if _, err := c.IMAPBanner(banner); err != nil {
					return err
				}
			} else {
				if _, err := c.Read(banner); err != nil {
					return err
				}
			}
		}
		if config.SendData {
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			msg := bytes.Replace(config.Data, []byte("%s"), []byte(host), -1)
			msg = bytes.Replace(msg, []byte("%d"), []byte(c.domain), -1)
			if _, err := c.Write(msg); err != nil {
				return err
			}
			if _, err := c.Read(response); err != nil {
				return err
			}
		}
		/*
			if config.Ehlo {
				if err := c.Ehlo(config.EhloDomain); err != nil {
					return err
				}
			}
			if config.SmtpHelp {
				if err := c.SmtpHelp(); err != nil {
					return err
				}
			}
			if config.StartTls {
				if config.Imap {
					if err := c.ImapStarttlsHandshake(); err != nil {
						return err
					}
				} else if config.Pop3 {
					if err := c.Pop3StarttlsHandshake(); err != nil {
						return err
					}
				} else {
					if err := c.SmtpStarttlsHandshake(); err != nil {
						return err
					}
				}
			}
		*/
		if config.Heartbleed {
			buf := make([]byte, 256)
			if _, err := c.CheckHeartbleed(buf); err != nil {
				return err
			}
		}
		return nil
	}
	// Wrap the whole thing in a logger
	return func(c *Conn) ([]ConnectionEvent, error) {
		err := g(c)
		if err != nil {
			config.Log.Errorf("Conversation error with remote host %s: %s",
				c.RemoteAddr().String(), err.Error())
		}
		return c.States(), err
	}
}

func GrabBanner(config *Config, target *GrabTarget) *Grab {
	dial := makeDialer(config)
	grabber := makeGrabber(config)
	port := strconv.FormatUint(uint64(config.Port), 10)
	addr := target.Addr.String()
	rhost := net.JoinHostPort(addr, port)
	t := time.Now()
	conn, dialErr := dial(rhost)
	if target.Domain != "" {
		conn.SetDomain(target.Domain)
	}
	if dialErr != nil {
		// Could not connect to host
		config.Log.Errorf("Could not connect to %s remote host %s: %s",
			target.Domain, addr, dialErr.Error())
		return &Grab{
			Host:   target.Addr,
			Domain: target.Domain,
			Time:   t,
			Log:    conn.States(),
		}
	}
	grabStates, _ := grabber(conn)
	return &Grab{
		Host:   target.Addr,
		Domain: target.Domain,
		Time:   t,
		Log:    grabStates,
	}
}
