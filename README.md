zgrab
==================

[![Build Status](https://travis-ci.org/zmap/zgrab.svg?branch=master)](https://travis-ci.org/zmap/zgrab)

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
$ zmap -p 443 --output-fields=* | ztee results.csv | zgrab --port 443 --tls --http="/" --output-file=banners.json
```

## Requirements

zgrab requires go version of at least 1.6. Please note that this is newer than the version included in Ubuntu 14.04 apt repository. You can install ztee from ZMap Github repository at https://github.com/zmap/zmap.


## ZGrab as a library / dependency

If you are using ZGrab code in another Go program, import ZGrab using [gopkg.in](http://gopkg.in). ZGrab tends to be very unstable, API's may break at any time, so be sure to vendor ZGrab.

## License

ZGrab is licensed under Apache 2.0 and ISC. For more information, see the LICENSE file.
