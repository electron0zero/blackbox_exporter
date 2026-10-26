// Copyright The Prometheus Authors
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

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// Targets served by badserver. The port table in badserver/main.go says what each port does.
const (
	httpOK     = "http://badserver:8080"
	wsEcho     = "ws://badserver:8080/ws/echo"
	tcpOpen    = "badserver:8080"
	dnsServer  = "badserver:53"
	icmpHost   = "badserver"
	grpcServer = "badserver:9090"
	// badserver has A and AAAA records, but this port listens on its IPv6 address only.
	grpcIPv6Only = "badserver:9091"
	proxyURL     = "http://badserver:3128"
)

var usedIPv6 = []metricWant{{name: "probe_ip_protocol", value: 6}}

// probeCases need the real image, raw sockets or container networking. Everything else is a unit test in prober/.
var probeCases = []probeCase{
	{prober: "http", name: "smoke", target: httpOK, want: 1},
	{
		prober: "http", name: "via proxy", target: httpOK + "/?via-proxy", want: 1,
		module: `{proxy_url: "` + proxyURL + `"}`,
		check: func(t *testing.T) {
			if got := mustGet(t, badserverURL+"/proxy/requests"); !strings.Contains(got, "/?via-proxy") {
				t.Errorf("proxy did not see the probe, requests:\n%s", got)
			}
		},
	},
	{prober: "tcp", name: "smoke", target: tcpOpen, want: 1},
	{
		prober: "dns", name: "smoke", target: dnsServer, want: 1,
		module: `{query_name: www.e2e.test, query_type: A, validate_answer_rrs: {fail_if_not_matches_regexp: ['192\.0\.2\.10']}}`,
	},
	{prober: "icmp", name: "smoke", target: icmpHost, want: 1},
	{
		prober: "icmp", name: "ipv6", target: icmpHost, want: 1, metrics: usedIPv6,
		module: `{preferred_ip_protocol: ip6, ip_protocol_fallback: false}`,
	},
	{prober: "icmp", name: "over mtu fragmented", target: icmpHost, want: 1, module: `{payload_size: 1500}`},
	// Also fails without the DF bit, since raw sockets are not fragmented. It checks the size error only.
	{
		prober: "icmp", name: "over mtu with dont_fragment", target: icmpHost, want: 0, wantLog: "message too long",
		module: `{dont_fragment: true, payload_size: 1500}`,
	},
	{prober: "grpc", name: "smoke", target: grpcServer, want: 1},
	{
		prober: "grpc", name: "ipv6 only listener", target: grpcIPv6Only, want: 1, metrics: usedIPv6,
		module: `{preferred_ip_protocol: ip6, ip_protocol_fallback: false}`,
	},
	{
		prober: "grpc", name: "ipv6 only listener with ip4 and no fallback", target: grpcIPv6Only, want: 0,
		module: `{ip_protocol_fallback: false}`,
		skip:   "grpc prober resolves the target but dials the hostname, so it connects over IPv6 while reporting probe_ip_protocol 4",
	},
	{
		prober: "websocket", name: "smoke", target: wsEcho, want: 1,
		module: `query_response: [{send: ping}, {expect: "^ping$"}]`,
	},
}

func TestProbes(t *testing.T) {
	for _, c := range probeCases {
		t.Run(c.moduleName(), func(t *testing.T) {
			if c.skip != "" {
				t.Skip(c.skip)
			}
			r := probe(t, c.moduleName(), c.target)
			if got, ok := r.value("probe_success", nil); !ok || got != c.want {
				t.Fatalf("probe_success = %v (present %v), want %v\nlogs:\n%s", got, ok, c.want, r.logs)
			}
			if c.wantLog != "" && !strings.Contains(r.logs, c.wantLog) {
				t.Errorf("logs do not contain %q:\n%s", c.wantLog, r.logs)
			}
			for _, m := range c.metrics {
				if v, ok := r.value(m.name, m.labels); !ok || v != m.value {
					t.Errorf("%s%v = %v (present %v), want %v", m.name, m.labels, v, ok, m.value)
				}
			}
			if c.check != nil {
				c.check(t)
			}
		})
	}
}
