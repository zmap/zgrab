// Copyright 2010 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/textproto"
	"sort"
	"strings"
)

// A Header represents the key-value pairs in an HTTP header.
type Header map[string][]string

// Add adds the key, value pair to the header.
// It appends to any existing values associated with key.
func (h Header) Add(key, value string) {
	textproto.MIMEHeader(h).Add(key, value)
}

// Set sets the header entries associated with key to
// the single element value.  It replaces any existing
// values associated with key.
func (h Header) Set(key, value string) {
	textproto.MIMEHeader(h).Set(key, value)
}

// Get gets the first value associated with the given key.
// If there are no values associated with the key, Get returns "".
// To access multiple values of a key, access the map directly
// with CanonicalHeaderKey.
func (h Header) Get(key string) string {
	return textproto.MIMEHeader(h).Get(key)
}

// Del deletes the values associated with key.
func (h Header) Del(key string) {
	textproto.MIMEHeader(h).Del(key)
}

// Write writes a header in wire format.
func (h Header) Write(w io.Writer) error {
	return h.WriteSubset(w, nil)
}

var headerNewlineToSpace = strings.NewReplacer("\n", " ", "\r", " ")

// WriteSubset writes a header in wire format.
// If exclude is not nil, keys where exclude[key] == true are not written.
func (h Header) WriteSubset(w io.Writer, exclude map[string]bool) error {
	keys := make([]string, 0, len(h))
	for k := range h {
		if exclude == nil || !exclude[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			v = headerNewlineToSpace.Replace(v)
			v = strings.TrimSpace(v)
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

// CanonicalHeaderKey returns the canonical format of the
// header key s.  The canonicalization converts the first
// letter and any letter following a hyphen to upper case;
// the rest are converted to lowercase.  For example, the
// canonical key for "accept-encoding" is "Accept-Encoding".
func CanonicalHeaderKey(s string) string { return textproto.CanonicalMIMEHeaderKey(s) }

func FormatHeaderName(s string) string {
	return strings.Replace(strings.ToLower(s), "-", "_", 30)
}

type UnknownHeader struct {
	Key    string   `json:"key,omitempty"`
	Values []string `json:"value,omitempty"`
}

func formatHeaderValues(v []string) {
	for idx := range v {
		if len(v[idx]) >= 8192 {
			v[idx] = v[idx][0:8191]
		}
	}
}

// Custom JSON Marshaller to comply with snake_case header names
func (h Header) MarshalJSON() ([]byte, error) {
	headerMap := make(map[string]interface{})
	for k, v := range h {
		// Need to special-case unknown header object, since it's not a true header (aka map[string][]string)
		if k == "Unknown" && len(v) > 0 {
			var unknownHeaders []UnknownHeader
			json.Unmarshal([]byte(v[0]), &unknownHeaders)
			for idx := range unknownHeaders {
				formatHeaderValues(unknownHeaders[idx].Values)
			}
			headerMap[FormatHeaderName(k)] = unknownHeaders
		} else {
			formatHeaderValues(v)
			headerMap[FormatHeaderName(k)] = v
		}
	}
	return json.Marshal(headerMap)
}
