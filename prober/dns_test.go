// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/blackbox_exporter/config"
)

var PROTOCOLS = [...]string{"udp", "tcp"}

// startDNSServer starts a DNS server with a given handler function on a random port.
// Returns the Server object itself as well as the net.Addr corresponding to the server port.
func startDNSServer(protocol string, handler func(dns.ResponseWriter, *dns.Msg)) (*dns.Server, net.Addr) {
	h := dns.NewServeMux()
	h.HandleFunc(".", handler)

	server := &dns.Server{Addr: ":0", Net: protocol, Handler: h}
	if protocol == "udp" {
		a, err := net.ResolveUDPAddr(server.Net, server.Addr)
		if err != nil {
			panic(err)
		}
		l, err := net.ListenUDP(server.Net, a)
		if err != nil {
			panic(err)
		}
		server.PacketConn = l
	} else {
		a, err := net.ResolveTCPAddr(server.Net, server.Addr)
		if err != nil {
			panic(err)
		}
		l, err := net.ListenTCP(server.Net, a)
		if err != nil {
			panic(err)
		}
		server.Listener = l
	}
	go server.ActivateAndServe()

	if protocol == "tcp" {
		return server, server.Listener.Addr()
	}
	return server, server.PacketConn.LocalAddr()
}

func recursiveDNSHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if !r.RecursionDesired {
		m.Rcode = dns.RcodeRefused
	} else {
		answers := []string{
			"example.com. 3600 IN A 127.0.0.1",
			"example.com. 3600 IN A 127.0.0.2",
		}
		for _, rr := range answers {
			a, err := dns.NewRR(rr)
			if err != nil {
				panic(err)
			}
			m.Answer = append(m.Answer, a)
		}
	}
	if err := w.WriteMsg(m); err != nil {
		panic(err)
	}
}

func TestRecursiveDNSResponse(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	tests := []struct {
		Probe         config.DNSProbe
		ShouldSucceed bool
	}{
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				Recursion:          true,
			}, true,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				Recursion:          true,
				ValidRcodes:        []string{"SERVFAIL", "NXDOMAIN"},
			}, false,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				Recursion:          true,
				ValidateAnswer: config.DNSRRValidator{
					FailIfMatchesRegexp:    []string{".*7200.*"},
					FailIfNotMatchesRegexp: []string{".*3600.*"},
				},
			}, true,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				Recursion:          true,
				ValidateAuthority: config.DNSRRValidator{
					FailIfMatchesRegexp: []string{".*7200.*"},
				},
			}, true,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				Recursion:          true,
				ValidateAdditional: config.DNSRRValidator{
					FailIfNotMatchesRegexp: []string{".*3600.*"},
				},
			}, false,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				Recursion:          false,
			}, false,
		},
	}

	for _, protocol := range PROTOCOLS {
		server, addr := startDNSServer(protocol, recursiveDNSHandler)
		defer server.Shutdown()

		for i, test := range tests {
			test.Probe.TransportProtocol = protocol
			registry := prometheus.NewPedanticRegistry()
			registry.Gather()

			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := ProbeDNS(testCTX, addr.String(), config.Module{Timeout: time.Second, DNS: test.Probe}, registry, promslog.NewNopLogger())
			if result != test.ShouldSucceed {
				t.Fatalf("Test %d had unexpected result: %v", i, result)
			}
			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			expectedResults := map[string]float64{
				"probe_dns_answer_rrs":      2,
				"probe_dns_authority_rrs":   0,
				"probe_dns_additional_rrs":  0,
				"probe_dns_query_succeeded": 1,
			}
			if !test.Probe.Recursion {
				expectedResults["probe_dns_answer_rrs"] = 0
			}
			checkRegistryResults(expectedResults, mfs, t)
		}
	}
}

func authoritativeDNSHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if r.Question[0].Qtype == dns.TypeSOA {
		a, err := dns.NewRR("example.com. 3600 IN SOA ns.example.com. noc.example.com. 1000 7200 3600 1209600 3600")
		if err != nil {
			panic(err)
		}
		m.Answer = append(m.Answer, a)
	} else if r.Question[0].Qclass == dns.ClassCHAOS && r.Question[0].Qtype == dns.TypeTXT {
		txt, err := dns.NewRR("example.com. 3600 CH TXT \"goCHAOS\"")
		if err != nil {
			panic(err)
		}
		m.Answer = append(m.Answer, txt)
	} else {
		a, err := dns.NewRR("example.com. 3600 IN A 127.0.0.1")
		if err != nil {
			panic(err)
		}
		m.Answer = append(m.Answer, a)
	}

	authority := []string{
		"example.com. 7200 IN NS ns1.isp.net.",
		"example.com. 7200 IN NS ns2.isp.net.",
	}
	for _, rr := range authority {
		a, err := dns.NewRR(rr)
		if err != nil {
			panic(err)
		}
		m.Ns = append(m.Ns, a)
	}

	additional := []string{
		"ns1.isp.net. 7200 IN A 127.0.0.1",
		"ns1.isp.net. 7200 IN AAAA ::1",
		"ns2.isp.net. 7200 IN A 127.0.0.2",
	}
	for _, rr := range additional {
		a, err := dns.NewRR(rr)
		if err != nil {
			panic(err)
		}
		m.Extra = append(m.Extra, a)
	}

	if err := w.WriteMsg(m); err != nil {
		panic(err)
	}
}

func TestAuthoritativeDNSResponse(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	tests := []struct {
		Probe         config.DNSProbe
		ShouldSucceed bool
	}{
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
			}, true,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				QueryType:          "SOA",
			}, true,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryClass:         "CH",
				QueryName:          "example.com",
				QueryType:          "TXT",
				ValidateAnswer: config.DNSRRValidator{
					FailIfMatchesRegexp:    []string{".*IN.*"},
					FailIfNotMatchesRegexp: []string{".*CH.*"},
				},
			}, true,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidRcodes:        []string{"SERVFAIL", "NXDOMAIN"},
			}, false,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAnswer: config.DNSRRValidator{
					FailIfMatchesRegexp:    []string{".*3600.*"},
					FailIfNotMatchesRegexp: []string{".*3600.*"},
				},
			}, false,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAnswer: config.DNSRRValidator{
					FailIfMatchesRegexp:    []string{".*7200.*"},
					FailIfNotMatchesRegexp: []string{".*7200.*"},
				},
			}, false,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAuthority: config.DNSRRValidator{
					FailIfNotMatchesRegexp: []string{"ns.*.isp.net"},
				},
			}, true,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAdditional: config.DNSRRValidator{
					FailIfNotMatchesRegexp: []string{"^ns.*.isp"},
				},
			}, true,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAdditional: config.DNSRRValidator{
					FailIfMatchesRegexp: []string{"^ns.*.isp"},
				},
			}, false,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAdditional: config.DNSRRValidator{
					FailIfAllMatchRegexp: []string{".*127.0.0.*"},
				},
			}, false,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidateAdditional: config.DNSRRValidator{
					FailIfNoneMatchesRegexp: []string{".*127.0.0.3.*"},
				},
			}, false,
		},
	}

	for _, protocol := range PROTOCOLS {
		server, addr := startDNSServer(protocol, authoritativeDNSHandler)
		defer server.Shutdown()

		for i, test := range tests {
			test.Probe.TransportProtocol = protocol
			registry := prometheus.NewRegistry()
			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := ProbeDNS(testCTX, addr.String(), config.Module{Timeout: time.Second, DNS: test.Probe}, registry, promslog.NewNopLogger())
			if result != test.ShouldSucceed {
				t.Fatalf("Test %d had unexpected result: %v", i, result)
			}
			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			expectedResults := map[string]float64{
				"probe_dns_answer_rrs":      1,
				"probe_dns_authority_rrs":   2,
				"probe_dns_additional_rrs":  3,
				"probe_dns_query_succeeded": 1,
			}
			if test.Probe.QueryType == "SOA" {
				expectedResults["probe_dns_serial"] = 1000
			}

			checkRegistryResults(expectedResults, mfs, t)
		}
	}
}

func TestServfailDNSResponse(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	tests := []struct {
		Probe         config.DNSProbe
		ShouldSucceed bool
	}{
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
			}, false,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidRcodes:        []string{"SERVFAIL", "NXDOMAIN"},
			}, true,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				QueryType:          "NOT_A_VALID_QUERY_TYPE",
			}, false,
		},
		{
			config.DNSProbe{
				IPProtocol:         "ip4",
				IPProtocolFallback: true,
				QueryName:          "example.com",
				ValidRcodes:        []string{"NOT_A_VALID_RCODE"},
			}, false,
		},
	}

	for _, protocol := range PROTOCOLS {
		// dns.HandleFailed returns SERVFAIL on everything
		server, addr := startDNSServer(protocol, dns.HandleFailed)
		defer server.Shutdown()

		for i, test := range tests {
			test.Probe.TransportProtocol = protocol
			registry := prometheus.NewRegistry()
			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := ProbeDNS(testCTX, addr.String(), config.Module{Timeout: time.Second, DNS: test.Probe}, registry, promslog.NewNopLogger())
			if result != test.ShouldSucceed {
				t.Fatalf("Test %d had unexpected result: %v", i, result)
			}
			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			expectedResults := map[string]float64{
				"probe_dns_answer_rrs":      0,
				"probe_dns_authority_rrs":   0,
				"probe_dns_additional_rrs":  0,
				"probe_dns_query_succeeded": 1,
			}

			// Handle case where ProbeDNS fails before executing the query because of an invalid query type
			if test.Probe.QueryType == "NOT_A_VALID_QUERY_TYPE" {
				expectedResults["probe_dns_query_succeeded"] = 0
			}

			checkRegistryResults(expectedResults, mfs, t)
		}
	}
}

func TestDNSProtocol(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skip("skipping; CI is failing on ipv6 dns requests")
	}

	// This test assumes that listening TCP listens both IPv6 and IPv4 traffic and
	// localhost resolves to both 127.0.0.1 and ::1. we must skip the test if either
	// of these isn't true. This should be true for modern Linux systems.
	if runtime.GOOS == "dragonfly" || runtime.GOOS == "openbsd" {
		t.Skip("IPv6 socket isn't able to accept IPv4 traffic in the system.")
	}
	_, err := net.ResolveIPAddr("ip6", "localhost")
	if err != nil {
		t.Skip("\"localhost\" doesn't resolve to ::1.")
	}

	for _, protocol := range PROTOCOLS {
		server, addr := startDNSServer(protocol, recursiveDNSHandler)
		defer server.Shutdown()

		_, port, _ := net.SplitHostPort(addr.String())

		// Prefer IPv6
		module := config.Module{
			Timeout: time.Second,
			DNS: config.DNSProbe{
				QueryName:         "example.com",
				TransportProtocol: protocol,
				IPProtocol:        "ip6",
				Recursion:         true,
			},
		}
		registry := prometheus.NewRegistry()
		testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result := ProbeDNS(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
		if !result {
			t.Fatalf("DNS protocol: \"%v\", preferred \"ip6\" connection test failed, expected success.", protocol)
		}
		mfs, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		expectedResults := map[string]float64{
			"probe_ip_protocol": 6,
		}
		checkRegistryResults(expectedResults, mfs, t)

		// Prefer IPv4
		module = config.Module{
			Timeout: time.Second,
			DNS: config.DNSProbe{
				QueryName:         "example.com",
				Recursion:         true,
				TransportProtocol: protocol,
				IPProtocol:        "ip4",
			},
		}
		registry = prometheus.NewRegistry()
		testCTX, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result = ProbeDNS(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
		if !result {
			t.Fatalf("DNS protocol: \"%v\", preferred \"ip4\" connection test failed, expected success.", protocol)
		}
		mfs, err = registry.Gather()
		if err != nil {
			t.Fatal(err)
		}

		expectedResults = map[string]float64{
			"probe_ip_protocol": 4,
		}
		checkRegistryResults(expectedResults, mfs, t)

		// Prefer none
		module = config.Module{
			Timeout: time.Second,
			DNS: config.DNSProbe{
				QueryName:         "example.com",
				Recursion:         true,
				TransportProtocol: protocol,
			},
		}
		registry = prometheus.NewRegistry()
		testCTX, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result = ProbeDNS(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
		if !result {
			t.Fatalf("DNS protocol: \"%v\" connection test failed, expected success.", protocol)
		}
		mfs, err = registry.Gather()
		if err != nil {
			t.Fatal(err)
		}

		expectedResults = map[string]float64{
			"probe_ip_protocol": 6,
		}
		checkRegistryResults(expectedResults, mfs, t)

		// No protocol
		module = config.Module{
			Timeout: time.Second,
			DNS: config.DNSProbe{
				QueryName: "example.com",
				Recursion: true,
			},
		}
		registry = prometheus.NewRegistry()
		testCTX, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result = ProbeDNS(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
		if protocol == "udp" {
			if !result {
				t.Fatalf("DNS test connection with protocol %s failed, expected success.", protocol)
			}
		} else {
			if result {
				t.Fatalf("DNS test connection with protocol %s succeeded, expected failure.", protocol)
			}
		}
		mfs, err = registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		expectedResults = map[string]float64{
			"probe_ip_protocol": 6,
		}
		checkRegistryResults(expectedResults, mfs, t)

	}
}

// TestDNSMetrics checks that calling ProbeDNS populates the expected
// set of metrics for a DNS probe, but it does not test that those
// metrics contain specific values.
func TestDNSMetrics(t *testing.T) {
	server, addr := startDNSServer("udp", recursiveDNSHandler)
	defer server.Shutdown()

	_, port, _ := net.SplitHostPort(addr.String())

	module := config.Module{
		Timeout: time.Second,
		DNS: config.DNSProbe{
			IPProtocol:         "ip4",
			IPProtocolFallback: true,
			QueryName:          "example.com",
			Recursion:          true,
		},
	}
	registry := prometheus.NewRegistry()
	testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := ProbeDNS(testCTX, net.JoinHostPort("localhost", port), module, registry, promslog.NewNopLogger())
	if !result {
		t.Fatalf("DNS test connection failed, expected success.")
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	expectedMetrics := map[string]map[string]map[string]struct{}{
		"probe_dns_lookup_time_seconds": nil,
		"probe_dns_duration_seconds": {
			"phase": {
				"resolve": {},
				"connect": {},
				"request": {},
			},
		},
		"probe_dns_answer_rrs":      nil,
		"probe_dns_authority_rrs":   nil,
		"probe_dns_additional_rrs":  nil,
		"probe_dns_query_succeeded": nil,
	}

	checkMetrics(expectedMetrics, mfs, t)
}

func TestDNSOverTLS(t *testing.T) {
	certExpiry := time.Now().AddDate(0, 0, 1)
	certTmpl := generateCertificateTemplate(certExpiry, true)
	certTmpl.IsCA = true
	_, certPem, key := generateSelfSignedCertificate(certTmpl)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	serverCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		t.Fatalf("Error decoding TLS keypair: %s", err)
	}

	// CAFile must be passed via filesystem.
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPem, 0o600); err != nil {
		t.Fatalf("Error writing CA file: %s", err)
	}

	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{serverCert}})
	if err != nil {
		t.Fatalf("Error listening on socket: %s", err)
	}
	h := dns.NewServeMux()
	h.HandleFunc(".", recursiveDNSHandler)
	server := &dns.Server{Net: "tcp-tls", Listener: ln, Handler: h}
	go server.ActivateAndServe()
	defer server.Shutdown()

	tests := []struct {
		serverName    string
		ShouldSucceed bool
	}{
		{"localhost", true},
		// Empty falls back to the target IP, which is in the cert's IP SANs.
		{"", true},
		{"wrong.example.com", false},
	}

	for i, test := range tests {
		module := config.Module{
			Timeout: time.Second,
			DNS: config.DNSProbe{
				IPProtocol:        "ip4",
				TransportProtocol: "tcp",
				DNSOverTLS:        true,
				QueryName:         "example.com",
				Recursion:         true,
				TLSConfig: pconfig.TLSConfig{
					CAFile:     caFile,
					ServerName: test.serverName,
				},
			},
		}
		registry := prometheus.NewRegistry()
		testCTX, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result := ProbeDNS(testCTX, ln.Addr().String(), module, registry, promslog.NewNopLogger())
		cancel()
		if result != test.ShouldSucceed {
			t.Fatalf("Test %d (server_name %q) had unexpected result: %v", i, test.serverName, result)
		}
	}
}

// truncatingTXTDNSHandler answers with a TXT record too large for a plain UDP response.
func truncatingTXTDNSHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{strings.Repeat("a", 255), strings.Repeat("b", 255), strings.Repeat("c", 255)},
	})
	if _, ok := w.LocalAddr().(*net.UDPAddr); ok {
		m.Truncate(dns.MinMsgSize)
	}
	if err := w.WriteMsg(m); err != nil {
		panic(err)
	}
}

func TestDNSTruncatedResponse(t *testing.T) {
	tests := []struct {
		protocol  string
		answerRRs float64
	}{
		// The TC flag is not surfaced or retried over TCP, see #1258.
		{"udp", 0},
		{"tcp", 1},
	}

	for _, test := range tests {
		server, addr := startDNSServer(test.protocol, truncatingTXTDNSHandler)
		defer server.Shutdown()
		_, port, _ := net.SplitHostPort(addr.String())

		module := config.Module{
			Timeout: time.Second,
			DNS: config.DNSProbe{
				IPProtocol:        "ip4",
				TransportProtocol: test.protocol,
				QueryName:         "example.com",
				QueryType:         "TXT",
			},
		}
		registry := prometheus.NewRegistry()
		testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if !ProbeDNS(testCTX, net.JoinHostPort("127.0.0.1", port), module, registry, promslog.NewNopLogger()) {
			t.Fatalf("DNS protocol %s probe failed, expected success.", test.protocol)
		}
		mfs, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		expectedResults := map[string]float64{
			"probe_dns_answer_rrs":      test.answerRRs,
			"probe_dns_query_succeeded": 1,
		}
		checkRegistryResults(expectedResults, mfs, t)
	}
}

func TestDNSSourceIPAddress(t *testing.T) {
	tests := []struct {
		sourceIP      string
		ShouldSucceed bool
	}{
		{"127.0.0.1", true},
		// TEST-NET-1 is never assigned locally, so binding to it must fail.
		{"192.0.2.1", false},
	}

	for _, protocol := range PROTOCOLS {
		server, addr := startDNSServer(protocol, recursiveDNSHandler)
		defer server.Shutdown()
		_, port, _ := net.SplitHostPort(addr.String())

		for _, test := range tests {
			module := config.Module{
				Timeout: time.Second,
				DNS: config.DNSProbe{
					IPProtocol:        "ip4",
					TransportProtocol: protocol,
					SourceIPAddress:   test.sourceIP,
					QueryName:         "example.com",
					Recursion:         true,
				},
			}
			registry := prometheus.NewRegistry()
			testCTX, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := ProbeDNS(testCTX, net.JoinHostPort("127.0.0.1", port), module, registry, promslog.NewNopLogger())
			if result != test.ShouldSucceed {
				t.Fatalf("DNS protocol %s with source_ip_address %s had unexpected result: %v", protocol, test.sourceIP, result)
			}
		}
	}
}
