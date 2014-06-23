package main

import (
	"./zutil"
	"./banner"
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

// Command-line flags
var (
	encoding                      string
	outputFileName, inputFileName string
	logFileName, metadataFileName string
	messageFileName               string
	interfaceName                 string
	portFlag                      uint
	inputFile, metadataFile       *os.File
	senders                       uint
)

// Module configurations
var (
	grabConfig   banner.GrabConfig
	outputConfig banner.OutputConfig
)

// Pre-main bind flags to variables
func init() {

	flag.StringVar(&encoding, "encoding", "string", "Encode banner as string|hex|base64")
	flag.StringVar(&outputFileName, "output-file", "-", "Output filename, use - for stdout")
	flag.StringVar(&inputFileName, "input-file", "-", "Input filename, use - for stdin")
	flag.StringVar(&messageFileName, "data", "", "Optional message to send (%s will be replaced with destination IP)")
	flag.StringVar(&metadataFileName, "metadata-file", "-", "File to record banner-grab metadata, use - for stdout")
	flag.StringVar(&logFileName, "log-file", "-", "File to log to, use - for stderr")
	flag.StringVar(&interfaceName, "interface", "", "Network interface to send on")
	flag.UintVar(&portFlag, "port", 80, "Port to grab on")
	flag.IntVar(&grabConfig.Timeout, "timeout", 4, "Set connection timeout in seconds")
	flag.BoolVar(&grabConfig.Tls, "tls", false, "Grab over TLS")
	flag.BoolVar(&grabConfig.Udp, "udp", false, "Grab over UDP")
	flag.UintVar(&senders, "senders", 1000, "Number of send coroutines to use")
	flag.BoolVar(&grabConfig.ReadFirst, "read-first", false, "Read data before sending anything")
	flag.BoolVar(&grabConfig.StartTls, "starttls", false, "Send STARTTLS before negotiating (implies --tls)")
	flag.BoolVar(&grabConfig.Heartbleed, "heartbleed", false, "Check if server is vulnerable to Heartbleed (implies --tls)")
	flag.Parse()

	// STARTTLS implies TLS
	if grabConfig.StartTls || grabConfig.Heartbleed {
		grabConfig.Tls = true
	}

	// Validate port
	if portFlag > 65535 {
		log.Fatal("Error: Port", portFlag, "out of range")
	}
	grabConfig.Port = uint16(portFlag)

	// Validate timeout
	if grabConfig.Timeout < 0 {
		log.Fatal("Error: Invalid timeout", grabConfig.Timeout)
	}

	// Check UDP
	if grabConfig.Udp {
		log.Print("Warning: UDP is untested")
	}

	// Validate senders
	if senders == 0 {
		log.Fatal("Error: Need at least one sender")
	}

	// Check output type
	if converter, ok := banner.Converters[encoding]; ok {
		outputConfig.Converter = converter
	} else {
		log.Fatal("Error: Invalid encoding ", encoding)
	}

	// Check the network interface
	var err error
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
			grabConfig.Message = string(buf[0:n])
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			messageFile.Close()
		}
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
	logger := log.New(logFile, "[BANNER-GRAB]", log.LstdFlags)
	outputConfig.ErrorLog = logger
	grabConfig.ErrorLog = logger
}

func ReadInput(addrChan chan net.IP, inputFile *os.File) {
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		ipString := scanner.Text()
		ip := net.ParseIP(ipString)
		if ip == nil {
			fmt.Fprintln(os.Stderr, "Invalid IP address: ", ipString)
			continue
		}

		addrChan <- ip
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Reading stdin: ", err)
	}
	close(addrChan)
}

func main() {
	addrInChan, addrOutChan := zutil.NewNonblockingSendPair()
	resultChan := make(chan banner.Result, senders)
	summaryChan := make(chan banner.Summary)
	doneChan := make(chan int)

	go banner.WriteOutput(resultChan, summaryChan, &outputConfig)
	for i := uint(0); i < senders; i += 1 {
		go banner.GrabBanner(addrOutChan, resultChan, doneChan, &grabConfig)
	}
	ReadInput(addrInChan, inputFile)

	// Wait for grabbers to finish
	for i := uint(0); i < senders; i += 1 {
		<-doneChan
	}
	close(doneChan)
	close(resultChan)

	if inputFile != os.Stdin {
		inputFile.Close()
	}
	if outputConfig.OutputFile != os.Stdout {
		outputConfig.OutputFile.Close()
	}

	summary := <-summaryChan
	if s, err := banner.SerializeSummary(&summary); err != nil {
		log.Fatal(err)
	} else {
		metadataFile.Write(s)
		metadataFile.Write([]byte("\n"))
	}
}
