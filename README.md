zgrab
==================

A TLS Banner Grabber, in Go

## Building

```
$ go build
```

## Usage

```
./banner-grab --help
```

## Example

```
$ zmap -p 443 --output-fields=* | ztee --output-file=results.csv | zgrab --port 443 --tls --data=./http-req --output-file=banners.json
```


