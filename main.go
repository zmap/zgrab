package main

import (
	"flag"
	"fmt"
	"log"
	"bufio"
	"os"
	"net"
	"./banner"
)

// Command-line flags
var (
	encoding, outputFileName, inputFileName string
	portFlag uint
	useTls, useUdp bool
	outputFile, inputFile *os.File
)

// Pre-main bind flags to variables
func init() {

	flag.StringVar(&encoding, "encoding", "string", "Encode banner as string|hex|base64")
	flag.StringVar(&outputFileName, "output-file", "-", "Output filename, use - for stdout")
	flag.StringVar(&inputFileName, "input-file", "-", "Input filename, use - for stdin")
	flag.UintVar(&portFlag, "port", 80, "Port to grab on")
	flag.BoolVar(&useTls, "tls", false, "Grab over TLS")
	flag.BoolVar(&useUdp, "udp", false, "Grab over UDP")
	flag.Parse()

	// Validate port
	if portFlag > 65535 {
		log.Fatal("Error: Port", portFlag, "out of range")
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
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	addrChan := make(chan net.IP)
	resultChan := make(chan banner.Result)
	go banner.WriteOutput(resultChan, converter, outputFile)
	go banner.GrabBanner(addrChan, resultChan)
	ReadInput(addrChan, inputFile)
}

