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
		fmt.Fprintf(w, TEST_SERVER_BODY)
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
		GOMAXPROCS: 1,
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

func getAddrAndPortForServer(s *httptest.Server) (net.IP, uint16) {
	var addr net.IP
	var port uint16
	if u, err := url.Parse(s.URL); err != nil {
		zlog.Fatal("Invalid URL %s", s.URL)
	} else {
		hostSlice := strings.Split(u.Host, ":")
		addr = net.ParseIP(hostSlice[0])
		if testPort, err := strconv.ParseUint(hostSlice[1], 10, 16); err != nil {
			zlog.Fatal("Unable to parse port %s", hostSlice[1])
		} else {
			port = uint16(testPort)
		}

	}

	return addr, port
}

func TestHTTPToHTTPSRedirect(t *testing.T) {

	var tlsServerHostString string

	tlsServer := httptest.NewTLSServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.TLS.ServerName != tlsServerHostString {
			t.Errorf("Wrong SNI - expected: %s, got: %s", tlsServerHostString, r.TLS.ServerName)
		}

		fmt.Fprintf(w, TEST_SERVER_BODY)
	}))
	defer tlsServer.Close()

	tlsServerAddr, tlsServerPort := getAddrAndPortForServer(tlsServer)

	tlsServerHostString = tlsServerAddr.String() + ":" + strconv.Itoa(int(tlsServerPort))

	var redirectServerAddr net.IP
	var redirectServerPort uint16

	redirectServer := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		redirectServerString := redirectServerAddr.String() + ":" + strconv.Itoa(int(redirectServerPort))
		if r.Host != redirectServerString {
			t.Errorf("Wrong HTTP Host - expected: %s, got: %s", redirectServerString, r.Host)
		}
		Redirect(w, r, "https://"+tlsServerHostString+"/", StatusMovedPermanently)
	}))
	defer redirectServer.Close()

	redirectServerAddr, redirectServerPort = getAddrAndPortForServer(redirectServer)

	config := &zlib.Config{
		Port:               redirectServerPort,
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
			MaxRedirects: 1,
		},
		ErrorLog:   zlog.New(os.Stderr, "banner-grab"),
		GOMAXPROCS: 1,
	}

	target := &zlib.GrabTarget{
		Addr:   redirectServerAddr,
		Domain: "",
	}

	grab := zlib.GrabBanner(config, target)
	httpData := grab.Data.HTTP
	if httpData.Response.Status != "200 OK" {
		t.Errorf("Unable to load page: Expected: 200 OK, got: %s", httpData.Response.Status)
	}
	if httpData.Response.BodyText != TEST_SERVER_BODY {
		t.Errorf("Unexpected HTTP response body")
	}
	if len(httpData.RedirectResponseChain) != 1 {
		t.Errorf("Incorrect number of redirects: Expected: 1, got: %s", httpData.RedirectResponseChain)
	}

	redirectResponse := httpData.RedirectResponseChain[0]
	if redirectResponse.Headers.Get("location") != "https://"+tlsServerHostString+"/" {
		t.Errorf("Wrong location header - Expected: %s, got: %s", "https://"+tlsServerHostString+"/", redirectResponse.Headers.Get("location"))
	}
}

// TODO: add tests for more complex HTTP behavior/options
