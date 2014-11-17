package zlib

import (
	"crypto/x509"
	"log"
	"time"
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
	ErrorLog *log.Logger
}

/*
Tls          bool
TlsVersion   uint16
Banners      bool
SendMessage  bool
ReadResponse bool
Smtp         bool
Ehlo         bool
SmtpHelp     bool
StartTls     bool
Imap         bool
Pop3         bool
Heartbleed   bool
Port         uint16
Timeout      time.Duration
Message      []byte
EhloDomain   string
Protocol     string
ErrorLog     *log.Logger
LocalAddr    net.Addr
RootCAPool   *x509.CertPool
CbcOnly      bool
*/
