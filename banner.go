package main

import (
	"fmt"
	"bufio"
	"os"
	"net"
	"io"
	"strings"
)

func readInput(addrChan chan net.IP) {
	fmt.Println("Reading input")
	scanner := bufio.NewScanner(os.Stdin)
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

func grabBanner(addrChan chan net.IP) {
	for ip := range addrChan {
		addr := ip.String()
		rhost := net.JoinHostPort(addr, "80")
		conn, err := net.Dial("tcp", rhost)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Could not connect to host: ", ip)
			continue
		}
		message := "GET / HTTP/1.1\nHost: %s\n\n\n"
		s := strings.Replace(message, "%s", addr, -1)
		if _, err := conn.Write([]byte(s)); err != nil {
			conn.Close()
			fmt.Fprintln(os.Stderr, "Could not write message to host: ", s)
			continue
		}
		var buf [1024]byte
		n, err := conn.Read(buf[:])
		conn.Close()
		if err != nil && (err != io.EOF || n == 0) {
			continue
		}
		fmt.Println("RESPONSE")
		fmt.Printf("%s\n", string(buf[0:n]))
		fmt.Println("END_RESPONSE")
	}
}

func main() {
	fmt.Println("Launching main")
	addrChan := make(chan net.IP)
	go grabBanner(addrChan)
	readInput(addrChan)
}

