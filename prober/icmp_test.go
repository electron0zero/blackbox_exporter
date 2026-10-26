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

package prober

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"golang.org/x/net/icmp"

	"github.com/prometheus/blackbox_exporter/config"
)

// skipUnlessICMPAvailable skips the test when neither an unprivileged nor a
// raw ICMP socket can be opened on addr.
func skipUnlessICMPAvailable(t *testing.T, unprivilegedNetwork, privilegedNetwork, addr string) {
	t.Helper()
	conn, err := icmp.ListenPacket(unprivilegedNetwork, addr)
	if err == nil {
		conn.Close()
		return
	}
	conn, rawErr := icmp.ListenPacket(privilegedNetwork, addr)
	if rawErr == nil {
		conn.Close()
		return
	}
	t.Skipf("skipping: cannot open ICMP socket on %s (unprivileged needs the GID in net.ipv4.ping_group_range on Linux, raw needs CAP_NET_RAW): %s: %v, %s: %v",
		addr, unprivilegedNetwork, err, privilegedNetwork, rawErr)
}

func TestICMPLoopback(t *testing.T) {
	tests := []struct {
		name                string
		target              string
		ipProtocol          string
		unprivilegedNetwork string
		privilegedNetwork   string
	}{
		{
			name:                "ipv4",
			target:              "127.0.0.1",
			ipProtocol:          "ip4",
			unprivilegedNetwork: "udp4",
			privilegedNetwork:   "ip4:icmp",
		},
		{
			name:                "ipv6",
			target:              "::1",
			ipProtocol:          "ip6",
			unprivilegedNetwork: "udp6",
			privilegedNetwork:   "ip6:ipv6-icmp",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			skipUnlessICMPAvailable(t, tc.unprivilegedNetwork, tc.privilegedNetwork, tc.target)

			module := config.Module{
				Timeout: time.Second,
				ICMP: config.ICMPProbe{
					IPProtocol: tc.ipProtocol,
				},
			}
			registry := prometheus.NewRegistry()
			testCTX, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if !ProbeICMP(testCTX, tc.target, module, registry, promslog.NewNopLogger()) {
				t.Fatalf("ICMP probe of %s failed, expected success.", tc.target)
			}

			mfs, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			expectedMetrics := map[string]map[string]map[string]struct{}{
				"probe_ip_protocol":             nil,
				"probe_ip_addr_hash":            nil,
				"probe_dns_lookup_time_seconds": nil,
				"probe_icmp_duration_seconds": {
					"phase": {
						"resolve": {},
						"setup":   {},
						"rtt":     {},
					},
				},
			}
			checkMetrics(expectedMetrics, mfs, t)

			// rtt is only set once a matching echo reply has been read.
			for _, mf := range mfs {
				if mf.GetName() != "probe_icmp_duration_seconds" {
					continue
				}
				for _, m := range mf.GetMetric() {
					if m.GetLabel()[0].GetValue() == "rtt" && m.GetGauge().GetValue() <= 0 {
						t.Fatalf("Expected probe_icmp_duration_seconds{phase=\"rtt\"} > 0, got %v", m.GetGauge().GetValue())
					}
				}
			}
		})
	}
}
