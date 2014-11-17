package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"strings"
	"time"
	"zgrab/zlib"
	"ztools/processing"
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
	senders                       uint
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
	mailStrPtr *string = nil
)

type Summary struct {
	Success    uint          `json:"success_count"`
	Error      uint          `json:"error_count"`
	Total      uint          `json:"total"`
	Protocol   string        `json:"protocol"`
	Port       uint16        `json:"port"`
	Start      time.Time     `json:"start_time"`
	End        time.Time     `json:"end_time"`
	Duration   time.Duration `json:"duration"`
	Timeout    uint          `json:"timeout"`
	Mail       *string       `json:"mail_type"`
	TlsVersion string        `json:"max_tls_version"`
	CAFileName string        `json:"ca_file"`
}

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
	flag.UintVar(&senders, "senders", 1000, "Number of send coroutines to use")
	flag.BoolVar(&config.Banners, "banners", false, "Read banner upon connection creation")
	flag.StringVar(&messageFileName, "data", "", "Send a message and read response (%s will be replaced with destination IP)")
	flag.StringVar(&config.EHLODomain, "ehlo", "", "Send an EHLO with the specified domain (implies --smtp)")
	flag.BoolVar(&config.SMTPHelp, "smtp-help", false, "Send a SMTP help (implies --smtp)")
	flag.BoolVar(&config.StartTLS, "starttls", false, "Send STARTTLS before negotiating")
	flag.BoolVar(&config.SMTP, "smtp", false, "Conform to SMTP when reading responses and sending STARTTLS")
	flag.BoolVar(&config.IMAP, "imap", false, "Conform to IMAP rules when sending STARTTLS")
	flag.BoolVar(&config.POP3, "pop3", false, "Conform to POP3 rules when sending STARTTLS")
	flag.BoolVar(&config.Heartbleed, "heartbleed", false, "Check if server is vulnerable to Heartbleed (implies --tls)")
	flag.StringVar(&rootCAFileName, "ca-file", "", "List of trusted root certificate authorities in PEM format")
	flag.BoolVar(&config.CBCOnly, "cbc-only", false, "Send only ciphers that use CBC")
	flag.Parse()

	// Validate TLS Versions
	tv := strings.ToUpper(tlsVersion)
	if tv != "" {
		config.TLS = true
	}

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
		log.Fatal("Invalid SSL/TLS versions")
	}

	// STARTTLS cannot be used with TLS
	if config.StartTLS && config.TLS {
		log.Fatal("Cannot both initiate a TLS and STARTTLS connection")
	}

	if config.EHLODomain != "" {
		config.EHLO = true
	}

	if config.SMTPHelp || config.EHLO {
		config.SMTP = true

	}

	if config.SMTP && (config.IMAP || config.POP3) {
		log.Fatal("Cannot conform to SMTP and IMAP/POP3 at the same time")
	}

	if config.IMAP && config.POP3 {
		log.Fatal("Cannot conform to IMAP and POP3 at the same time")
	}

	if config.EHLO && (config.IMAP || config.POP3) {
		log.Fatal("Cannot send an EHLO when conforming to IMAP or POP3")
	}

	// Heartbleed requires STARTTLS or TLS
	if config.Heartbleed && !(config.StartTLS || config.TLS) {
		log.Fatal("Must specify one of --tls or --starttls for --heartbleed")
	}

	// Validate port
	if portFlag > 65535 {
		log.Fatal("Port", portFlag, "out of range")
	}
	config.Port = uint16(portFlag)

	// Validate timeout
	config.Timeout = time.Duration(timeout) * time.Second

	// Validate senders
	if senders == 0 {
		log.Fatal("Error: Need at least one sender")
	}

	// Check output type

	// Check the network interface
	var err error
	/*
		if interfaceName != "" {
			var iface *net.Interface
			if iface, err = net.InterfaceByName(interfaceName); err != nil {
				log.Fatal("Error: Invalid network interface: ", interfaceName)
			}
			var addrs []net.Addr
			if addrs, err = iface.Addrs(); err != nil || len(addrs) == 0 {
				log.Fatal("Error: No addresses for interface ", interfaceName)
			}
			grabConfig.LocalAddr = addrs[0]
		}
	*/

	// Look at CA file
	if rootCAFileName != "" {
		var fd *os.File
		if fd, err = os.Open(rootCAFileName); err != nil {
			log.Fatal(err)
		}
		caBytes, readErr := ioutil.ReadAll(fd)
		if readErr != nil {
			log.Fatal(err)
		}
		config.RootCAPool = x509.NewCertPool()
		ok := config.RootCAPool.AppendCertsFromPEM(caBytes)
		if !ok {
			log.Fatal("Could not read certificates from PEM file. Invalid PEM?")
		}
	}

	// Open input and output files
	switch inputFileName {
	case "-":
		inputFile = os.Stdin
	default:
		if inputFile, err = os.Open(inputFileName); err != nil {
			log.Fatal(err)
		}
	}

	switch outputFileName {
	case "-":
		outputConfig.OutputFile = os.Stdout
	default:
		if outputConfig.OutputFile, err = os.Create(outputFileName); err != nil {
			log.Fatal(err)
		}
	}

	// Open message file, if applicable
	if messageFileName != "" {
		if messageFile, err := os.Open(messageFileName); err != nil {
			log.Fatal(err)
		} else {
			buf := make([]byte, 1024)
			n, err := messageFile.Read(buf)
			config.SendData = true
			config.Data = buf[0:n]
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			messageFile.Close()
		}
	}

	// Open metadata file
	/*
		if metadataFileName == "-" {
			metadataFile = os.Stdout
		} else {
			if metadataFile, err = os.Create(metadataFileName); err != nil {
				log.Fatal(err)
			}
		}
	*/

	// Open log file, attach to configs
	var logFile *os.File
	if logFileName == "-" {
		logFile = os.Stderr
	} else {
		if logFile, err = os.Create(logFileName); err != nil {
			log.Fatal(err)
		}
	}
	logger := log.New(logFile, "[BANNER-GRAB] ", log.LstdFlags)
	config.ErrorLog = logger
}

type EncoderTest struct {
	enc *json.Encoder
}

func (e *EncoderTest) Encode(v interface{}) error {
	val := reflect.ValueOf(&v)
	p := reflect.Indirect(val).Interface()
	log.Print(reflect.TypeOf(p))
	log.Print(reflect.TypeOf(&p))
	return e.enc.Encode(p)
}

func main() {
	decoder := zlib.NewGrabTargetDecoder(inputFile)
	encoder := json.NewEncoder(outputConfig.OutputFile)
	worker := zlib.NewGrabWorker(&config)
	processing.Process(decoder, encoder, worker, senders)
}
