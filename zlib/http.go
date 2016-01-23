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

package zlib

import (
	"github.com/zmap/zgrab/ztools/http"
	"github.com/zmap/zgrab/ztools/util"
	"net"
	"net/url"
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
	VersionMajor int         `json:"version_major",omitempty"`
	VersionMinor int         `json:"version_minor",omitempty"`
	StatusCode   int         `json:"status_code,omitempty"`
	StatusLine   string      `json:"status_line,omitempty"`
	Headers      HTTPHeaders `json:"headers,omitempty"`
	Body         string      `json:"body,omitempty"`
	BodySHA256   []byte      `json:"body_sha256,omitempty"`
}

type HTTP struct {
	ProxyRequest          *HTTPRequest     `json:"connect_request,omitempty"`
	ProxyResponse         *HTTPResponse    `json:"connect_response,omitempty"`
	Response              *http.Response   `json:"response,omitempty"`
	RedirectResponseChain []*http.Response `json:"redirect_response_chain,omitempty"`
}

type HTTPRequestResponse struct {
	Request  *HTTPRequest  `json:"request,omitempty"`
	Response *HTTPResponse `json:"response,omitempty"`
}

func init() {
	dropHeaders = make(map[string]int, 8)
	dropHeaders["cookie"] = 1
	dropHeaders["date"] = 1
	dropHeaders["etag"] = 1
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
	knownHeaders["expires"] = 1
	knownHeaders["last_modified"] = 1
	knownHeaders["link"] = 1
	knownHeaders["location"] = 1
	knownHeaders["p3p"] = 1
	knownHeaders["pragma"] = 1
	knownHeaders["proxy_agent"] = 1
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
	knownHeaders["x_real_ip"] = 1
	knownHeaders["x_forwarded_for"] = 1
}

func (response HTTPResponse) isRedirect() bool {
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return true
	}

	return false
}

func (response HTTPResponse) canRedirectWithConn(conn *Conn) bool {

	targetUrl, targetUrlError := url.Parse(conn.domain)
	if targetUrlError != nil {
		return false
	}

	locationHeaders, ok := response.Headers["location"]
	if !ok || locationHeaders == nil {
		return false
	}

	redirectUrl, redirectUrlError := url.Parse(locationHeaders.(string))
	if redirectUrlError != nil {
		return false
	}

	remoteIpAddress, _, remoteIpAddressErr := net.SplitHostPort(conn.RemoteAddr().String())
	if remoteIpAddressErr != nil {
		return false
	}

	targetHost := targetUrl.Host
	if targetHost == "" {
		targetHost = conn.domain
	}
	redirectHost := redirectUrl.Host

	relativePath := redirectHost == ""
	matchesHost := (strings.Contains(redirectHost, targetHost) && util.TLDMatches(redirectHost, targetHost)) ||
		(redirectHost == remoteIpAddress)
	matchesProto := (conn.isTls && redirectUrl.Scheme == "https") || (!conn.isTls && redirectUrl.Scheme == "http")

	// Either explicit keep-alive or HTTP 1.1, which uses persistent connections by default
	var keepAlive bool
	if response.Headers["Connection"] != nil {
		keepAlive = strings.EqualFold(response.Headers["Connection"].(string), "keep-alive")
	} else {
		keepAlive = response.VersionMajor == 1 && response.VersionMinor == 1

	}

	return (relativePath && keepAlive) || (!relativePath && keepAlive && matchesHost && matchesProto)
}
