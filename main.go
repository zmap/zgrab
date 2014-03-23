package main

import (
	"flag"
	"fmt"
	"log"
	"bufio"
	"os"
	"net"
	"io"
	"./banner"
)

// Command-line flags
var (
	encoding, outputFileName, inputFileName, messageFileName string
	portFlag uint
	outputFile, inputFile *os.File
)

var (
	config banner.GrabConfig
)

// Pre-main bind flags to variables
func init() {

	flag.StringVar(&encoding, "encoding", "string", "Encode banner as string|hex|base64")
	flag.StringVar(&outputFileName, "output-file", "-", "Output filename, use - for stdout")
	flag.StringVar(&inputFileName, "input-file", "-", "Input filename, use - for stdin")
	flag.StringVar(&messageFileName, "data", "", "Optional message to send (%s will be replaced with destination IP)")
	flag.UintVar(&portFlag, "port", 80, "Port to grab on")
	flag.IntVar(&config.Timeout, "timeout", 4, "Set connection timeout in seconds")
	flag.BoolVar(&config.Tls, "tls", false, "Grab over TLS")
	flag.BoolVar(&config.Udp, "udp", false, "Grab over UDP")
	flag.BoolVar(&config.Summary, "summary", false, "Print a summary when finished")
	flag.Parse()

	// Validate port
	if portFlag > 65535 {
		log.Fatal("Error: Port", portFlag, "out of range")
	}
	config.Port = uint16(portFlag)

	// Validate timeout
	if config.Timeout < 0 {
		log.Fatal("Error: Invalid timeout", config.Timeout)
	}


	// Open input and output files
	var err error
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
		outputFile = os.Stdout
	default:
		if outputFile, err = os.Open(outputFileName); err != nil {
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
			config.SendMessage = true
			config.Message = string(buf[0:n])
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			messageFile.Close()
		}
	}
}

func ReadInput(addrChan chan net.IP, inputFile *os.File) {
	fmt.Println("Reading input")
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
	converter, err := banner.NewResultConverter(encoding)
	if err != nil {
		log.Fatal(err)
	}
	addrChan := make(chan net.IP)
	resultChan := make(chan banner.Result)

	go banner.WriteOutput(resultChan, converter, outputFile)
	go banner.GrabBanner(addrChan, resultChan, &config)
	ReadInput(addrChan, inputFile)
	if inputFile != os.Stdin {
		inputFile.Close()
	}
	if outputFile != os.Stdout {
		outputFile.Close()
	}
}

