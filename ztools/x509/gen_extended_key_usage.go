// The following directive is necessary to make the package coherent:

// +build ignore

// This program generates extended_key_usage.go. It can be invoked by running
// `$ go generate`
package main

import (
	"bytes"
	"encoding/csv"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	COLUMN_IDX_OID        = 0
	COLUMN_IDX_SHORT_NAME = 2
)

func writeHeader(out io.Writer) {
	s := `// Created by extended_key_usage_gen; DO NOT EDIT

// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 parses X.509-encoded keys and certificates.
package x509

import (
	"encoding/asn1"
)

`
	out.Write([]byte(s))
}

func goNameFromShortName(shortName, prefix string) string {
	parts := strings.Split(shortName, "-")
	for idx, p := range parts {
		if prefix == "" && idx == 0 {
			continue
		}
		parts[idx] = strings.Title(p)
	}
	return prefix + strings.Join(parts, "")
}

func oidDeclFromString(oid string) string {
	parts := strings.Split(oid, ".")
	buffer := bytes.Buffer{}
	buffer.WriteString("asn1.ObjectIdentifier{")
	for idx, p := range parts {
		buffer.WriteString(p)
		if idx != len(parts)-1 {
			buffer.WriteString(", ")
		}
	}
	buffer.WriteString("}")
	return buffer.String()
}

func generateASN1(oidToName map[string]string) string {
	buffer := bytes.Buffer{}
	for oid, shortName := range oidToName {
		goName := goNameFromShortName(shortName, "oid")
		oidDecl := oidDeclFromString(oid)
		buffer.WriteString(goName)
		buffer.WriteString(" = ")
		buffer.WriteString(oidDecl)
		buffer.WriteString("\n")
	}
	return buffer.String()
}

func main() {
	out, err := os.Create("herp.go")
	if err != nil {
		panic(err.Error())
	}
	defer out.Close()
	writeHeader(out)

	resp, err := http.Get("https://raw.githubusercontent.com/zmap/constants/master/x509/extended_key_usage.csv")
	if err != nil {
		panic(err.Error())
	}
	defer resp.Body.Close()

	oidToName := make(map[string]string)
	r := csv.NewReader(resp.Body)
	for lines := 0; ; lines++ {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err.Error())
		}
		if lines == 0 {
			// Header row
			continue
		}
		oid := record[COLUMN_IDX_OID]
		shortName := record[COLUMN_IDX_SHORT_NAME]
		oidToName[oid] = shortName
	}
	out.Write([]byte("var (\n"))
	oidDecls := generateASN1(oidToName)
	out.Write([]byte(oidDecls))
	out.Write([]byte(")\n"))
}
