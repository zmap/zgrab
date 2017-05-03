/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/zlint"

	log "github.com/Sirupsen/logrus"
)

type InputFormatType int

const (
	InputFormatBase64 InputFormatType = iota
	InputFormatPEM    InputFormatType = iota
)

var inputFormatArg string

func scannerSplitPEM(data []byte, atEOF bool) (int, []byte, error) {
	block, rest := pem.Decode(data)
	if block != nil {
		size := len(data) - len(rest)
		return size, data[:size], nil
	}
	return 0, nil, nil
}

func main() {
	flag.StringVar(&inputFormatArg, "format", "pem", "one of {pem, base64}")
	flag.Parse()

	inputFormatArg = strings.ToLower(inputFormatArg)
	log.SetLevel(log.InfoLevel)

	var inputFormat InputFormatType
	var splitter bufio.SplitFunc
	switch inputFormatArg {
	case "pem":
		inputFormat = InputFormatPEM
		splitter = scannerSplitPEM
	case "base64":
		inputFormat = InputFormatBase64
		splitter = bufio.ScanLines
	default:
		log.Fatalf("invalid --format: provided %s", inputFormatArg)
	}

	if flag.NArg() != 1 {
		log.Fatal("no path to certificate provided")
	}

	filename := flag.Arg(0)
	f, err := os.Open(filename)
	if err != nil {
		log.Fatalf("could not open file %s: %s", filename, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(splitter)

	for scanner.Scan() {
		var certBytes []byte
		switch inputFormat {
		case InputFormatPEM:
			p, _ := pem.Decode(scanner.Bytes())
			if p == nil {
				log.Warnf("could not parse pem")
				continue
			}
			certBytes = p.Bytes
		case InputFormatBase64:
			b := scanner.Bytes()
			certBytes = make([]byte, base64.StdEncoding.DecodedLen(len(b)))
			n, err := base64.StdEncoding.Decode(certBytes, b)
			if err != nil {
				log.Warnf("could not decode base64: %s", err)
				continue
			}
			certBytes = certBytes[0:n]
		default:
			panic("unreachable")
		}

		x509Cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			log.Warnf("unable to parse certificate: %s", err)
			continue
		}

		zlintReport, err := runZlint(x509Cert)
		if err != nil {
			log.Warnf("unable to run zlint: %s", err)
			continue
		}

		finalJSON, err := appendZlintToCertificate(x509Cert, zlintReport)

		if err != nil {
			log.Warnf("unable to append Zlint to certificate: %s", err)
			continue
		}
		fmt.Println(string(finalJSON))
	}

}

func runZlint(x509Cert *x509.Certificate) (map[string]string, error) {
	zlintReport, err := zlint.ParsedTestHandler(x509Cert)
	if err != nil {
		return nil, err
	}
	return zlintReport, nil
}

func appendZlintToCertificate(x509Cert *x509.Certificate, lintResult map[string]string) ([]byte, error) {
	return json.Marshal(struct {
		Raw      []byte            `json:"raw"`
		CertData *x509.Certificate `json:"parsed"`
		Zlint    map[string]string `json:"zlint"`
	}{
		Raw:      x509Cert.Raw,
		CertData: x509Cert,
		Zlint:    lintResult,
	})
}
