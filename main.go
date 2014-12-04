package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"
	"zgrab/zlib"
	"ztools/processing"
	"ztools/zlog"
	"ztools/ztls"
)

// Command-line flags
var (
	encoding                      string
	outputFileName, inputFileName string
	logFileName, metadataFileName string
	messageFileName               string
	interfaceName                 string
	ehlo                          string
	portFlag                      uint
	inputFile, metadataFile       *os.File
	udp                           bool
	timeout                       uint
	tlsVersion                    string
	rootCAFileName                string
)

// Module configurations
var (
	config       zlib.Config
	outputConfig zlib.OutputConfig
)

var (
	mailType string
)

// Pre-main bind flags to variables
func init() {

	flag.StringVar(&encoding, "encoding", "string", "Encode banner as string|hex|base64")
	flag.StringVar(&outputFileName, "output-file", "-", "Output filename, use - for stdout")
	flag.StringVar(&inputFileName, "input-file", "-", "Input filename, use - for stdin")
	flag.StringVar(&metadataFileName, "metadata-file", "-", "File to record banner-grab metadata, use - for stdout")
	flag.StringVar(&logFileName, "log-file", "-", "File to log to, use - for stderr")
	flag.StringVar(&interfaceName, "interface", "", "Network interface to send on")
	flag.UintVar(&portFlag, "port", 80, "Port to grab on")
	flag.UintVar(&timeout, "timeout", 10, "Set connection timeout in seconds")
	flag.BoolVar(&config.TLS, "tls", false, "Grab over TLS")
	flag.StringVar(&tlsVersion, "tls-version", "", "Max TLS version to use (implies --tls)")
	flag.BoolVar(&udp, "udp", false, "Grab over UDP")
	flag.UintVar(&config.Senders, "senders", 1000, "Number of send coroutines to use")
	flag.BoolVar(&config.Banners, "banners", false, "Read banner upon connection creation")
	flag.StringVar(&messageFileName, "data", "", "Send a message and read response (%s will be replaced with destination IP)")
	flag.StringVar(&config.EHLODomain, "ehlo", "", "Send an EHLO with the specified domain (implies --smtp)")
	flag.BoolVar(&config.SMTPHelp, "smtp-help", false, "Send a SMTP help (implies --smtp)")
	flag.BoolVar(&config.StartTLS, "starttls", false, "Send STARTTLS before negotiating")
	flag.BoolVar(&config.SMTP, "smtp", false, "Conform to SMTP when reading responses and sending STARTTLS")
	flag.BoolVar(&config.IMAP, "imap", false, "Conform to IMAP rules when sending STARTTLS")
	flag.BoolVar(&config.POP3, "pop3", false, "Conform to POP3 rules when sending STARTTLS")
	flag.BoolVar(&config.Modbus, "modbus", false, "Send some modbus data")
	flag.BoolVar(&config.Heartbleed, "heartbleed", false, "Check if server is vulnerable to Heartbleed (implies --tls)")
	flag.StringVar(&rootCAFileName, "ca-file", "", "List of trusted root certificate authorities in PEM format")
	flag.BoolVar(&config.CBCOnly, "cbc-only", false, "Send only ciphers that use CBC")
	flag.Parse()

	// Validate TLS Versions
	tv := strings.ToUpper(tlsVersion)
	if tv != "" {
		config.TLS = true
	}

	if config.TLS {

		switch tv {
		case "SSLV3", "SSLV30", "SSLV3.0":
			config.TLSVersion = ztls.VersionSSL30
			tlsVersion = "SSLv3"
		case "TLSV1", "TLSV10", "TLSV1.0":
			config.TLSVersion = ztls.VersionTLS10
			tlsVersion = "TLSv1.0"
		case "TLSV11", "TLSV1.1":
			config.TLSVersion = ztls.VersionTLS11
			tlsVersion = "TLSv1.1"
		case "", "TLSV12", "TLSV1.2":
			config.TLSVersion = ztls.VersionTLS12
			tlsVersion = "TLSv1.2"
		default:
			zlog.Fatal("Invalid SSL/TLS versions")
		}
	}

	// STARTTLS cannot be used with TLS
	if config.StartTLS && config.TLS {
		zlog.Fatal("Cannot both initiate a TLS and STARTTLS connection")
	}

	if config.EHLODomain != "" {
		config.EHLO = true
	}

	if config.SMTPHelp || config.EHLO {
		config.SMTP = true

	}

	if config.SMTP && (config.IMAP || config.POP3) {
		zlog.Fatal("Cannot conform to SMTP and IMAP/POP3 at the same time")
	}

	if config.IMAP && config.POP3 {
		zlog.Fatal("Cannot conform to IMAP and POP3 at the same time")
	}

	if config.EHLO && (config.IMAP || config.POP3) {
		zlog.Fatal("Cannot send an EHLO when conforming to IMAP or POP3")
	}

	if config.SMTP {
		mailType = "SMTP"
	} else if config.POP3 {
		mailType = "POP3"
	} else if config.IMAP {
		mailType = "IMAP"
	}

	// Heartbleed requires STARTTLS or TLS
	if config.Heartbleed && !(config.StartTLS || config.TLS) {
		zlog.Fatal("Must specify one of --tls or --starttls for --heartbleed")
	}

	// Validate port
	if portFlag > 65535 {
		zlog.Fatal("Port", portFlag, "out of range")
	}
	config.Port = uint16(portFlag)

	// Validate timeout
	config.Timeout = time.Duration(timeout) * time.Second

	// Validate senders
	if config.Senders == 0 {
		zlog.Fatal("Error: Need at least one sender")
	}

	// Check the network interface
	var err error

	// Look at CA file
	if rootCAFileName != "" {
		var fd *os.File
		if fd, err = os.Open(rootCAFileName); err != nil {
			zlog.Fatal(err)
		}
		caBytes, readErr := ioutil.ReadAll(fd)
		if readErr != nil {
			zlog.Fatal(err)
		}
		config.RootCAPool = x509.NewCertPool()
		ok := config.RootCAPool.AppendCertsFromPEM(caBytes)
		if !ok {
			zlog.Fatal("Could not read certificates from PEM file. Invalid PEM?")
		}
	}

	// Open input and output files
	switch inputFileName {
	case "-":
		inputFile = os.Stdin
	default:
		if inputFile, err = os.Open(inputFileName); err != nil {
			zlog.Fatal(err)
		}
	}

	switch outputFileName {
	case "-":
		outputConfig.OutputFile = os.Stdout
	default:
		if outputConfig.OutputFile, err = os.Create(outputFileName); err != nil {
			zlog.Fatal(err)
		}
	}

	// Open message file, if applicable
	if messageFileName != "" {
		if messageFile, err := os.Open(messageFileName); err != nil {
			zlog.Fatal(err)
		} else {
			buf := make([]byte, 1024)
			n, err := messageFile.Read(buf)
			config.SendData = true
			config.Data = buf[0:n]
			if err != nil && err != io.EOF {
				zlog.Fatal(err)
			}
			messageFile.Close()
		}
	}

	// Open metadata file
	if metadataFileName == "-" {
		metadataFile = os.Stdout
	} else {
		if metadataFile, err = os.Create(metadataFileName); err != nil {
			zlog.Fatal(err)
		}
	}

	// Open log file, attach to configs
	var logFile *os.File
	if logFileName == "-" {
		logFile = os.Stderr
	} else {
		if logFile, err = os.Create(logFileName); err != nil {
			zlog.Fatal(err)
		}
	}
	logger := zlog.New(logFile, "banner-grab")
	config.ErrorLog = logger
}

func main() {
	decoder := zlib.NewGrabTargetDecoder(inputFile)
	encoder := json.NewEncoder(outputConfig.OutputFile)
	worker := zlib.NewGrabWorker(&config)
	start := time.Now()
	processing.Process(decoder, encoder, worker, config.Senders)
	end := time.Now()
	s := Summary{
		Port:       config.Port,
		Success:    worker.Success(),
		Failure:    worker.Failure(),
		Total:      worker.Total(),
		StartTime:  start,
		EndTime:    end,
		Duration:   end.Sub(start),
		Senders:    config.Senders,
		Timeout:    config.Timeout,
		TLSVersion: tlsVersion,
		MailType:   mailType,
	}
	enc := json.NewEncoder(metadataFile)
	if err := enc.Encode(&s); err != nil {
		config.ErrorLog.Errorf("Unable to write summary: %s", err.Error())
	}
}
