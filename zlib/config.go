package zlib

import (
	"crypto/x509"
	"time"

	"github.com/zmap/ztools/zlog"
)

type Config struct {
	// Connection
	Port    uint16
	Timeout time.Duration
	Senders uint

	// TLS
	TLS        bool
	TLSVersion uint16
	Heartbleed bool
	RootCAPool *x509.CertPool

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
	CBCOnly    bool
	EHLO       bool
	StartTLS   bool

	// Modbus
	Modbus bool

	// Error handling
	ErrorLog *zlog.Logger
}
