package zlib

import (
	"crypto/x509"
	"time"
	"ztools/zlog"
)

type Config struct {
	// Connection
	Port    uint16
	Timeout time.Duration

	// TLS
	TLS        bool
	TLSVersion uint16
	Heartbleed bool
	RootCAPool *x509.CertPool

	// Banners
	Banners  bool
	SendData bool
	Data     []byte

	// Mail
	SMTP       bool
	IMAP       bool
	POP3       bool
	SMTPHelp   bool
	EHLODomain string
	CBCOnly    bool
	EHLO       bool
	StartTLS   bool

	// Error handling
	Log *zlog.Logger
}
