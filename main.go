package main

import (
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"zgrab/banner"
	"zgrab/zcrypto/ztls"
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
	grabConfig   banner.GrabConfig
	outputConfig banner.OutputConfig
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
	flag.BoolVar(&grabConfig.Tls, "tls", false, "Grab over TLS")
	flag.StringVar(&tlsVersion, "tls-version", "", "Max TLS version to use (implies --tls)")
	flag.BoolVar(&udp, "udp", false, "Grab over UDP")
	flag.UintVar(&senders, "senders", 1000, "Number of send coroutines to use")
	flag.BoolVar(&grabConfig.Banners, "banners", false, "Read banner upon connection creation")
	flag.StringVar(&messageFileName, "data", "", "Send a message and read response (%s will be replaced with destination IP)")
	flag.StringVar(&grabConfig.EhloDomain, "ehlo", "", "Send an EHLO with the specified domain (implies --smtp)")
	flag.BoolVar(&grabConfig.SmtpHelp, "smtp-help", false, "Send a SMTP help (implies --smtp)")
	flag.BoolVar(&grabConfig.StartTls, "starttls", false, "Send STARTTLS before negotiating")
	flag.BoolVar(&grabConfig.Smtp, "smtp", false, "Conform to SMTP when reading responses and sending STARTTLS")
	flag.BoolVar(&grabConfig.Imap, "imap", false, "Conform to IMAP rules when sending STARTTLS")
	flag.BoolVar(&grabConfig.Pop3, "pop3", false, "Conform to POP3 rules when sending STARTTLS")
	flag.BoolVar(&grabConfig.Heartbleed, "heartbleed", false, "Check if server is vulnerable to Heartbleed (implies --tls)")
	flag.StringVar(&rootCAFileName, "ca-file", "", "List of trusted root certificate authorities in PEM format")
	flag.BoolVar(&grabConfig.CbcOnly, "cbc-only", false, "Send only ciphers that use CBC")
	flag.Parse()

	// Validate TLS Versions
	tv := strings.ToUpper(tlsVersion)
	if tv != "" {
		grabConfig.Tls = true
	}

	switch tv {
	case "SSLV3", "SSLV30", "SSLV3.0":
		grabConfig.TlsVersion = ztls.VersionSSL30
		tlsVersion = "SSLv3"
	case "TLSV1", "TLSV10", "TLSV1.0":
		grabConfig.TlsVersion = ztls.VersionTLS10
		tlsVersion = "TLSv1.0"
	case "TLSV11", "TLSV1.1":
		grabConfig.TlsVersion = ztls.VersionTLS11
		tlsVersion = "TLSv1.1"
	case "", "TLSV12", "TLSV1.2":
		grabConfig.TlsVersion = ztls.VersionTLS12
		tlsVersion = "TLSv1.2"
	default:
		log.Fatal("Invalid SSL/TLS versions")
	}

	// STARTTLS cannot be used with TLS
	if grabConfig.StartTls && grabConfig.Tls {
		log.Fatal("Cannot both initiate a TLS and STARTTLS connection")
	}

	if grabConfig.EhloDomain != "" {
		grabConfig.Ehlo = true
	}

	if grabConfig.SmtpHelp || grabConfig.Ehlo {
		grabConfig.Smtp = true

	}

	if grabConfig.Smtp && (grabConfig.Imap || grabConfig.Pop3) {
		log.Fatal("Cannot conform to SMTP and IMAP/POP3 at the same time")
	}

	if grabConfig.Smtp {
		mailStr := "smtp"
		mailStrPtr = &mailStr
	} else if grabConfig.Imap {
		mailStr := "imap"
		mailStrPtr = &mailStr
	} else if grabConfig.Pop3 {
		mailStr := "pop3"
		mailStrPtr = &mailStr
	}

	if grabConfig.Imap && grabConfig.Pop3 {
		log.Fatal("Cannot conform to IMAP and POP3 at the same time")
	}

	if grabConfig.Ehlo && (grabConfig.Imap || grabConfig.Pop3) {
		log.Fatal("Cannot send an EHLO when conforming to IMAP or POP3")
	}

	// Set mail type

	// Heartbleed requires STARTTLS or TLS
	if grabConfig.Heartbleed && !(grabConfig.StartTls || grabConfig.Tls) {
		log.Fatal("Must specify one of --tls or --starttls for --heartbleed")
	}

	// Validate port
	if portFlag > 65535 {
		log.Fatal("Port", portFlag, "out of range")
	}
	grabConfig.Port = uint16(portFlag)

	// Validate timeout
	grabConfig.Timeout = time.Duration(timeout) * time.Second

	// Check UDP
	if udp {
		log.Print("Warning: UDP is untested")
		grabConfig.Protocol = "udp"
	} else {
		grabConfig.Protocol = "tcp"
	}

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
		grabConfig.RootCAPool = x509.NewCertPool()
		ok := grabConfig.RootCAPool.AppendCertsFromPEM(caBytes)
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
			grabConfig.SendMessage = true
			grabConfig.Message = buf[0:n]
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			messageFile.Close()
		}
	}

	if grabConfig.ReadResponse && !grabConfig.SendMessage {
		log.Fatal("--read-response requires --data to be sent")
	}

	// Open metadata file
	if metadataFileName == "-" {
		metadataFile = os.Stdout
	} else {
		if metadataFile, err = os.Create(metadataFileName); err != nil {
			log.Fatal(err)
		}
	}

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
	outputConfig.ErrorLog = logger
	grabConfig.ErrorLog = logger
}

func ReadInput(addrChan chan banner.GrabTarget, inputFile *os.File) {
	r := csv.NewReader(inputFile)
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error reading stdin: %s", err.Error())
		}
		// Ignore blank lines
		if len(row) < 1 {
			continue
		}
		ipString := row[0]
		ip := net.ParseIP(ipString)
		if ip == nil {
			fmt.Fprintln(os.Stderr, "Invalid IP address: ", ipString)
			continue
		}
		var domain string
		if len(row) >= 2 {
			domain = row[1]
		}
		remoteHost := banner.GrabTarget{
			Addr:   ip,
			Domain: domain,
		}

		addrChan <- remoteHost
	}
	close(addrChan)
}

func (s *Summary) AddProgress(p *banner.Progress) {
	s.Success += p.Success
	s.Error += p.Error
	s.Total += p.Total
}

func main() {
	addrChan := make(chan banner.GrabTarget, senders*4)
	grabChan := make(chan banner.Grab, senders*4)
	doneChan := make(chan banner.Progress)
	outputDoneChan := make(chan int)

	s := Summary{
		Start:      time.Now(),
		Protocol:   grabConfig.Protocol,
		Port:       grabConfig.Port,
		Timeout:    timeout,
		Mail:       mailStrPtr,
		TlsVersion: tlsVersion,
		CAFileName: rootCAFileName,
	}

	go banner.WriteOutput(grabChan, outputDoneChan, &outputConfig)
	for i := uint(0); i < senders; i += 1 {
		go banner.GrabBanner(addrChan, grabChan, doneChan, &grabConfig)
	}
	ReadInput(addrChan, inputFile)

	// Wait for grabbers to finish
	for i := uint(0); i < senders; i += 1 {
		finalProgress := <-doneChan
		s.AddProgress(&finalProgress)
	}
	close(grabChan)
	close(doneChan)
	s.End = time.Now()
	s.Duration = s.End.Sub(s.Start) / time.Second

	<-outputDoneChan
	close(outputDoneChan)

	if inputFile != os.Stdin {
		inputFile.Close()
	}
	if outputConfig.OutputFile != os.Stdout {
		outputConfig.OutputFile.Close()
	}

	enc := json.NewEncoder(metadataFile)
	if err := enc.Encode(s); err != nil {
		log.Fatal(err)
	}
}
