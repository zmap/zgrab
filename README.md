zgrab
==================

[![Build Status](https://travis-ci.org/zmap/zgrab.svg?branch=master)](https://travis-ci.org/zmap/zgrab)
[![Go Report Card](https://goreportcard.com/badge/github.com/zmap/zgrab)](https://goreportcard.com/report/github.com/zmap/zgrab)

A Banner Grabber, in Go

## Building

You will need to have a valid `$GOPATH` set up, for more information about `$GOPATH`, see https://golang.org/doc/code.html.

Once you have a working `$GOPATH`, run:

```
go get github.com/zmap/zgrab
```

This will install zgrab under `$GOPATH/src/github.com/zmap/zgrab`

```
$ cd $GOPATH/src/github.com/zmap/zgrab
$ go build
```

## Usage

```
Usage of ./zgrab:
  -bacnet
    	Send some BACNet data
  -banners
    	Read banner upon connection creation
  -ca-file string
    	List of trusted root certificate authorities in PEM format
  -chrome-ciphers
    	Send Chrome Ordered Cipher Suites
  -chrome-no-dhe-ciphers
    	Send chrome ciphers minus DHE suites
  -connections-per-host uint
    	Number of times to connect to each host (results in more output) (default 1)
  -data string
    	Send a message and read response (%s will be replaced with destination IP)
  -dhe-ciphers
    	Send only DHE ciphers (not ECDHE)
  -dnp3
    	Read DNP3 banners
  -ecdhe-ciphers
    	Send only ECDHE ciphers (not DHE)
  -ehlo string
    	Send an EHLO with the specified domain (implies --smtp)
  -export-ciphers
    	Send only export ciphers
  -export-dhe-ciphers
    	Send only export DHE ciphers
  -firefox-ciphers
    	Send Firefox Ordered Cipher Suites
  -follow-localhost-redirects
    	Follow HTTP redirects to localhost (default true)
  -fox
    	Send some Niagara Fox Tunneling data
  -ftp
    	Read FTP banners
  -ftp-authtls
    	Collect FTPS certificates in addition to FTP banners
  -gomaxprocs int
    	Set GOMAXPROCS (default 3) (default 3)
  -heartbleed
    	Check if server is vulnerable to Heartbleed (implies --tls)
  -http string
    	Send an HTTP request to an endpoint
  -http-max-redirects int
    	Max number of redirects to follow
  -http-max-size int
    	Max kilobytes to read in response to an HTTP request (default 256)
  -http-method string
    	Set HTTP request method type (default "GET")
  -http-proxy-domain string
    	Send a CONNECT <domain> first
  -http-user-agent string
    	Set a custom HTTP user agent (default "Mozilla/5.0 zgrab/0.x")
  -imap
    	Conform to IMAP rules when sending STARTTLS
  -input-file string
    	Input filename, use - for stdin (default "-")
  -interface string
    	Network interface to send on
  -log-file string
    	File to log to, use - for stderr (default "-")
  -lookup-domain
    	Input contains only domain names
  -metadata-file string
    	File to record banner-grab metadata, use - for stdout (default "-")
  -modbus
    	Send some modbus data
  -no-sni
    	Do not send domain name in TLS handshake regardless of whether known
  -output-file string
    	Output filename, use - for stdout (default "-")
  -pop3
    	Conform to POP3 rules when sending STARTTLS
  -port uint
    	Port to grab on (default 80)
  -prometheus string
    	Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled.
  -raw-client-hello string
    	Provide a raw ClientHello to be sent; only the SNI will be rewritten
  -s7
    	Send some Siemens S7 data
  -safari-ciphers
    	Send Safari Ordered Cipher Suites
  -safari-no-dhe-ciphers
    	Send Safari ciphers minus DHE suites
  -senders uint
    	Number of send coroutines to use (default 1000)
  -signed-certificate-timestamp
    	request SCTs during TLS handshake (default true)
  -smb
    	Scan for SMB
  -smb-protocol int
    	Specify which SMB protocol to scan for (default 1)
  -smtp
    	Conform to SMTP when reading responses and sending STARTTLS
  -smtp-help
    	Send a SMTP help (implies --smtp)
  -starttls
    	Send STARTTLS before negotiating
  -telnet
    	Read telnet banners
  -telnet-max-size int
    	Max bytes to read for telnet banner (default 65536)
  -timeout uint
    	Set connection timeout in seconds (default 10)
  -tls
    	Grab over TLS
  -tls-extended-master-secret
    	Offer RFC 7627 Extended Master Secret extension
  -tls-extended-random
    	send extended random extension
  -tls-session-ticket
    	Send support for TLS Session Tickets and output ticket if presented
  -tls-verbose
    	Add extra TLS information to JSON output (client hello, client KEX, key material, etc)
  -tls-version string
    	Max TLS version to use (implies --tls)
  -xssh
    	Use the x/crypto SSH scanner
  -xssh-ciphers value
    	A comma-separated list of which ciphers to offer (default "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,arcfour256,arcfour128")
  -xssh-client-id string
    	Specify the client ID string to use (default "SSH-2.0-Go")
  -xssh-gex-max-bits uint
    	The maximum number of bits for the DH GEX prime. (default 8192)
  -xssh-gex-min-bits uint
    	The minimum number of bits for the DH GEX prime. (default 1024)
  -xssh-gex-preferred-bits uint
    	The preferred number of bits for the DH GEX prime. (default 2048)
  -xssh-host-key-algorithms value
    	A comma-separated list of which host key algorithms to offer (default "ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss,ssh-ed25519")
  -xssh-kex-algorithms value
    	A comma-separated list of which DH key exchange algorithms to offer (default "curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1")
  -xssh-userauth
    	Use the 'none' authentication request to see what userauth methods are allowed.
  -xssh-verbose
    	Output additional information.
```

## Example

```
$ zmap -p 443 --output-fields=* | ztee results.csv | zgrab --port 443 --tls --http="/" --output-file=banners.json
```

## Requirements

zgrab requires go version of at least 1.8.1. Please note that this is newer than the version included in Ubuntu 14.04 apt repository. You can install ztee from ZMap Github repository at https://github.com/zmap/zmap.


## ZGrab as a library / dependency

ZGrab tends to be very unstable, API's may break at any time, so be sure to vendor ZGrab.

## License

ZGrab is licensed under Apache 2.0 and ISC. For more information, see the LICENSE file.
