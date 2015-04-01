package zlib

import (
	"time"

	"github.com/zmap/zgrab/ztools/x509"
	"github.com/zmap/zgrab/ztools/zlog"
)

type Config struct {
	// Connection
	Port    uint16
	Timeout time.Duration
	Senders uint

	// Encoding
	Encoding string

	// TLS
	TLS           bool
	TLSVersion    uint16
	Heartbleed    bool
	RootCAPool    *x509.CertPool
	CBCOnly       bool
	SChannelOnly  bool
	DHEOnly       bool
	ExportsOnly   bool
	ExportsDHOnly bool
	FirefoxOnly   bool
	ChromeOnly    bool
	ChromeNoDHE   bool

	// SSH
	SSH bool

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

	// FTP
	FTP bool

	// Modbus
	Modbus bool

	// Error handling
	ErrorLog *zlog.Logger

	// Go Runtime Config
	GOMAXPROCS int
}
