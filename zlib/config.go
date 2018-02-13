/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package zlib

import (
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zgrab/ztools/zlog"
)

type HTTPConfig struct {
	Method                   string
	Endpoint                 string
	Headers                  string
	UserAgent                string
	ProxyDomain              string
	MaxSize                  int
	MaxRedirects             int
	FollowLocalhostRedirects bool
}

type XSSHScanConfig struct {
	XSSH bool
}

type SMBScanConfig struct {
	SMB      bool
	Protocol int
}

type Config struct {
	// Connection
	Port               uint16
	Timeout            time.Duration
	Senders            uint
	ConnectionsPerHost uint

	// DNS
	LookupDomain bool

	// TLS
	TLS                           bool
	TLSVersion                    uint16
	Heartbleed                    bool
	RootCAPool                    *x509.CertPool
	DHEOnly                       bool
	ECDHEOnly                     bool
	ExportsOnly                   bool
	ExportsDHOnly                 bool
	FirefoxOnly                   bool
	FirefoxNoDHE                  bool
	ChromeOnly                    bool
	ChromeNoDHE                   bool
	SafariOnly                    bool
	SafariNoDHE                   bool
	NoSNI                         bool
	TLSExtendedRandom             bool
	GatherSessionTicket           bool
	ExtendedMasterSecret          bool
	TLSVerbose                    bool
	SignedCertificateTimestampExt bool
	ExternalClientHello           []byte
	TLSCertsOnly                  bool

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
	FTP        bool
	FTPAuthTLS bool

	// Telnet
	Telnet        bool
	TelnetMaxSize int

	// Modbus
	Modbus bool

	// BACNet
	BACNet bool

	// Niagara Fox
	Fox bool

	// DNP3
	DNP3 bool

	// S7
	S7 bool

	// HTTP
	HTTP HTTPConfig

	// Error handling
	ErrorLog *zlog.Logger

	// Go Runtime Config
	GOMAXPROCS int

	// x/crypto SSH
	XSSH XSSHScanConfig

	// SMB
	SMB SMBScanConfig
}
