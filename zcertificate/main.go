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
	"encoding/json"
	"io"
	"os"
	"log"
	"bytes"
	"encoding/pem"
	"fmt"

	"github.com/zmap/zgrab/ztools/x509"
)

func main() {

	if len(os.Args) != 2 {
		log.Fatal("No path to certificate provided")
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal("Could not open specified certificate:", err)
	}
	buf := bytes.NewBuffer(nil)
	io.Copy(buf, f)

	p, _ := pem.Decode(buf.Bytes())
	if p == nil {
		log.Fatal("Unable to parse PEM file: ", err)
	}
	x509Cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		log.Fatal("Unable to parse certificate: ", err)
	}

	out, err := json.Marshal(x509Cert)
	if err != nil {
		log.Fatal("Unable to convert certificate to JSON: ", err)
	}
	fmt.Println(string(out))
}
