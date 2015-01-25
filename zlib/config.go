package zlib

import (
	"time"

	"github.com/zmap/ztools/x509"
	"github.com/zmap/ztools/zlog"
)

type Config struct {
	// Connection
	Port    uint16
	Timeout time.Duration
	Senders uint

	// Encoding
	Encoding string

	// TLS
	TLS          bool
	TLSVersion   uint16
	Heartbleed   bool
	RootCAPool   *x509.CertPool
	CBCOnly      bool
	SChannelOnly bool

	// Banners and Data
	Banners  bool
	SendData bool
	Data     []byte
	Raw      bool

	// Mail
	SMTP       bool
	IMAP       bool
	POP3       bool
	SMTPHelp   bool
	EHLODomain string
	EHLO       bool
	StartTLS   bool

	// Modbus
	Modbus bool

	// Error handling
	ErrorLog *zlog.Logger

	// Go Runtime Config
	GOMAXPROCS int
}
