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

// Command badserver is the e2e test target. It serves HTTP, websocket, DNS, gRPC and a forward proxy.
//
// Ports, also named in e2e/probes_test.go:
//
//	8080               HTTP: /, /ws/echo, /proxy/requests
//	53                 DNS over UDP: www.e2e.test A, NXDOMAIN for anything else
//	3128               forward proxy
//	9090               gRPC health, all addresses
//	-grpc-ipv6-listen  gRPC health on the IPv6 address only
package main

import (
	"flag"
	"log"
	"net"
)

func main() {
	grpcIPv6 := flag.String("grpc-ipv6-listen", "", "IPv6-only address for the second gRPC health listener.")
	flag.Parse()
	if *grpcIPv6 == "" {
		log.Fatal("-grpc-ipv6-listen is required")
	}

	p := &proxy{}

	// Every listener is open before anything serves, so the healthcheck on 8080 covers all ports.
	httpL := listen(":8080")
	dnsL, err := net.ListenPacket("udp", ":53")
	fatal(err)
	proxyL := listen(":3128")
	grpcL := listen(":9090")
	grpc6L := listen(*grpcIPv6)

	go serveHTTP(httpL, p)
	go serveDNS(dnsL)
	go p.serve(proxyL)
	go serveGRPC(grpcL)
	go serveGRPC(grpc6L)
	log.Print("badserver ready")
	select {}
}

func listen(addr string) net.Listener {
	l, err := net.Listen("tcp", addr)
	fatal(err)
	return l
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
