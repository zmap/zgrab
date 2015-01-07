zgrab
==================

A TLS Banner Grabber, in Go

## Building

You will need to have a valid `$GOPATH` set up, for more information about `$GOPATH`, see https://golang.org/doc/code.html. 

The ztools repository is located at https://github.com/zmap/ztools.

Once you have a working `$GOPATH` 

`go get github.com/zmap/zgrab`

once it has installed zgrab and ztools under `$GOPATH/src/github.com/zmap/zgrab` and `$GOPATH/src/github.com/zmap/ztools`

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

zgrab requires go version of at least 1.3.3
