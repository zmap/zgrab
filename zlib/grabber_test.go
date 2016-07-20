package zlib_test

import (
	"fmt"
	"github.com/zmap/zgrab/zlib"
	. "github.com/zmap/zgrab/ztools/http"
	"github.com/zmap/zgrab/ztools/http/httptest"
	"github.com/zmap/zgrab/ztools/zlog"
	"github.com/zmap/zgrab/ztools/ztls"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const TEST_SERVER_BODY = "Great Success!"

func TestHTTP(t *testing.T) {
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Last-Modified", "sometime")
		fmt.Fprintf(w, TEST_SERVER_BODY)
		if r.Host != "localhost" {
			t.Errorf("Wrong Host - expected: %s, got: %s", "localhost", r.Host)
		}
		if r.Method != "GET" {
			t.Errorf("Wrong Method - expected: %s, got: %s", "GET", r.Method)
		}
		if r.Protocol.Name != "HTTP/1.1" {
			t.Errorf("Wrong Protocol - expected: %s, got: %s", "HTTP/1.1", r.Protocol.Name)
		}
		if len(r.Headers) != 2 || r.Headers.Get("User-Agent") != "test UA" || r.Headers.Get("Accept-Encoding") != "gzip" {
			t.Errorf("Wrong headers: Expected User-Agent and Accept-Encoding, Got %s", r.Headers)
		}
	}))
	defer ts.Close()

	var addr net.IP
	var port uint16
	if u, err := url.Parse(ts.URL); err != nil {
		t.Errorf("Invalid URL %s", ts.URL)
	} else {
		hostSlice := strings.Split(u.Host, ":")
		addr = net.ParseIP(hostSlice[0])
		if testPort, err := strconv.ParseUint(hostSlice[1], 10, 16); err != nil {
			t.Errorf("Unable to parse port %s", hostSlice[1])
		} else {
			port = uint16(testPort)
		}

	}

	config := &zlib.Config{
		Port:               port,
		Timeout:            time.Duration(3) * time.Second,
		TLS:                false,
		TLSVersion:         ztls.VersionTLS12,
		Senders:            1,
		ConnectionsPerHost: 1,
		HTTP: zlib.HTTPConfig{
			Endpoint:     "/",
			Method:       "GET",
			UserAgent:    "test UA",
			MaxSize:      256,
			MaxRedirects: 0,
		},
		ErrorLog:   zlog.New(os.Stderr, "banner-grab"),
		GOMAXPROCS: 3,
	}

	target := &zlib.GrabTarget{
		Addr:   addr,
		Domain: "localhost",
	}

	grab := zlib.GrabBanner(config, target)
	httpResponse := grab.Data.HTTP.Response
	if httpResponse.Status != "200 OK" {
		t.Errorf("Unable to load page: Expected: 200 OK, got: %s", httpResponse.Status)
	}
	if httpResponse.BodyText != TEST_SERVER_BODY {
		t.Errorf("Unexpected HTTP response body")
	}
}

// TODO: add test for multiple root stores

// TODO: add test for more complex HTTP behavior/options
