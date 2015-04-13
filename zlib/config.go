package zlib

import (
	"encoding/csv"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/zmap/zgrab/ztools/ssh"
	"github.com/zmap/zgrab/ztools/x509"
	"github.com/zmap/zgrab/ztools/zlog"
)

type SSHScanConfig struct {
	SSH               bool
	Client            string
	KexAlgorithms     string
	HostKeyAlgorithms string
}

func (sc *SSHScanConfig) GetClientImplementation() (*ssh.ClientImplementation, bool) {
	if sc.Client == "" {
		return &ssh.OpenSSH_6_6p1, true
	}
	return ssh.ClientImplementationByName(sc.Client)
}

func (sc *SSHScanConfig) readNameList(reader io.Reader) (ssh.NameList, error) {
	csvReader := csv.NewReader(reader)
	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) != 1 {
		return nil, errors.New("TAHW")
	}
	nameList := ssh.NameList(records[0])
	return nameList, nil
}

func (sc *SSHScanConfig) MakeKexNameList() (ssh.NameList, error) {
	if sc.KexAlgorithms == "" {
		c, _ := sc.GetClientImplementation()
		return c.KexAlgorithms(), nil
	}
	kexReader := strings.NewReader(sc.KexAlgorithms)
	return sc.readNameList(kexReader)
}

func (sc *SSHScanConfig) MakeHostKeyNameList() (ssh.NameList, error) {
	if sc.HostKeyAlgorithms == "" {
		c, _ := sc.GetClientImplementation()
		return c.HostKeyAlgorithms(), nil
	}
	hostKeyReader := strings.NewReader(sc.HostKeyAlgorithms)
	return sc.readNameList(hostKeyReader)
}

func (sc *SSHScanConfig) MakeConfig() *ssh.Config {
	config := new(ssh.Config)
	config.KexAlgorithms, _ = sc.MakeKexNameList()
	config.HostKeyAlgorithms, _ = sc.MakeHostKeyNameList()
	return config
}

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
	FirefoxNoDHE  bool
	ChromeOnly    bool
	ChromeNoDHE   bool
	SafariOnly    bool
	SafariNoDHE   bool
	NoSNI         bool

	// SSH
	SSH SSHScanConfig

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
