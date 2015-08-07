/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zlib

import (
	"net/http"
	"strings"
)

var knownHeaders map[string]int
var dropHeaders map[string]int

type UnknownHeader struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

type HTTPHeaders map[string]interface{}

func HeadersFromGolangHeaders(h http.Header) HTTPHeaders {
	var out HTTPHeaders = make(map[string]interface{}, len(h))
	var unknownHeaders []UnknownHeader
	for header, values := range h {
		header = strings.ToLower(header)
		header = strings.Replace(header, "-", "_", -1)
		joined := strings.Join(values, ",")
		if len(joined) > 256 {
			joined = joined[0:256]
		}
		if _, ok := dropHeaders[header]; ok {
			continue
		} else if _, ok := knownHeaders[header]; ok {
			out[header] = joined
		} else {
			unk := UnknownHeader{
				Key:   header,
				Value: joined,
			}
			unknownHeaders = append(unknownHeaders, unk)
		}
	}
	if len(unknownHeaders) > 0 {
		out["unknown"] = unknownHeaders
	}
	return out
}

type HTTPRequest struct {
	Method    string `json:"method,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Body      string `json:"body,omitempty"`
}

type HTTPResponse struct {
	StatusCode int         `json:"status_code,omitempty"`
	StatusLine string      `json:"status_line,omitempty"`
	Headers    HTTPHeaders `json:"headers,omitempty"`
	Body       string      `json:"body,omitempty"`
	BodySHA256 []byte      `json:"body_sha256,omitempty"`
}

type HTTPRequestResponse struct {
	ProxyRequest  *HTTPRequest  `json:"connect_request,omitempty"`
	ProxyResponse *HTTPResponse `json:"connect_response,omitempty"`
	Request       *HTTPRequest  `json:"request,omitempty"`
	Response      *HTTPResponse `json:"response,omitempty"`
}

func init() {
	dropHeaders = make(map[string]int, 8)
	dropHeaders["date"] = 1
	dropHeaders["set_cookie"] = 1

	knownHeaders = make(map[string]int, 128)
	knownHeaders["access_control_allow_origin"] = 1
	knownHeaders["accept_patch"] = 1
	knownHeaders["accept_ranges"] = 1
	knownHeaders["age"] = 1
	knownHeaders["allow"] = 1
	knownHeaders["cache_control"] = 1
	knownHeaders["connection"] = 1
	knownHeaders["content_disposition"] = 1
	knownHeaders["content_encoding"] = 1
	knownHeaders["content_language"] = 1
	knownHeaders["content_length"] = 1
	knownHeaders["content_location"] = 1
	knownHeaders["content_md5"] = 1
	knownHeaders["content_range"] = 1
	knownHeaders["content_type"] = 1
	knownHeaders["etag"] = 1
	knownHeaders["expires"] = 1
	knownHeaders["last_modified"] = 1
	knownHeaders["link"] = 1
	knownHeaders["location"] = 1
	knownHeaders["p3p"] = 1
	knownHeaders["pragma"] = 1
	knownHeaders["proxy_authenticate"] = 1
	knownHeaders["public_key_pins"] = 1
	knownHeaders["refresh"] = 1
	knownHeaders["retry_after"] = 1
	knownHeaders["server"] = 1
	knownHeaders["set_cookie"] = 1
	knownHeaders["status"] = 1
	knownHeaders["strict_transport_security"] = 1
	knownHeaders["trailer"] = 1
	knownHeaders["transfer_encoding"] = 1
	knownHeaders["upgrade"] = 1
	knownHeaders["vary"] = 1
	knownHeaders["via"] = 1
	knownHeaders["warning"] = 1
	knownHeaders["www_authenticate"] = 1
	knownHeaders["x_frame_options"] = 1
	knownHeaders["x_xss_protection"] = 1
	knownHeaders["content_security_policy"] = 1
	knownHeaders["x_content_security_policy"] = 1
	knownHeaders["x_webkit_csp"] = 1
	knownHeaders["x_content_type_options"] = 1
	knownHeaders["x_powered_by"] = 1
	knownHeaders["x_ua_compatible"] = 1
	knownHeaders["x_content_duration"] = 1

}
