zgrab
==================

A TLS Banner Grabber, in Go

## Building

You will need to have a valid `$GOPATH` set up, and this repository should exist in `$GOPATH/src/zgrab`. For more information about `$GOPATH`, see https://golang.org/doc/code.html.

Once you have a working `$GOPATH`, run:

```
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


