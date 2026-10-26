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

package main

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

func serveDNS(pc net.PacketConn) {
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(handleDNS)}
	fatal(srv.ActivateAndServe())
}

func handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	if q := req.Question; len(q) == 1 && strings.EqualFold(q[0].Name, "www.e2e.test.") && q[0].Qtype == dns.TypeA {
		rr, err := dns.NewRR("www.e2e.test. 300 IN A 192.0.2.10")
		fatal(err)
		m.Answer = []dns.RR{rr}
	} else {
		m.Rcode = dns.RcodeNameError
	}
	w.WriteMsg(m)
}
