zgrab
==================

A TLS Banner Grabber, in Go

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
./zgrab --help
```

## Example

```
$ zmap -p 443 --output-fields=* | ztee --output-file=results.csv | zgrab --port 443 --tls --data=./http-req --output-file=banners.json
```

## Requirements

zgrab requires go version of at least 1.3.3. Please note that this is newer than the version included in Ubuntu 14.04 apt repository. You can install ztee from ZMap Github repository at https://github.com/zmap/zmap.
