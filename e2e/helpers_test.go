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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"go.yaml.in/yaml/v3"
)

const composeFile = "compose.yaml"

// compose runs docker compose against the e2e stack and returns its combined output.
func compose(args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"compose", "-f", composeFile}, args...)...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// probeCase is one row of probeCases. Each case becomes its own exporter module, named by moduleName.
type probeCase struct {
	prober string
	name   string
	target string
	// module is the YAML of the prober's section. preferred_ip_protocol defaults to ip4.
	module string
	want   float64
	// wantLog must appear in the probe logs, so a failing case fails for the intended reason.
	wantLog string
	metrics []metricWant
	// check runs after the probe, for effects outside the exporter.
	check func(t *testing.T)
	// skip is set for open bugs. The fix removes it.
	skip string
}

func (c probeCase) moduleName() string {
	return c.prober + "_" + strings.ReplaceAll(c.name, " ", "_")
}

// metricWant is a series a probe must expose with the given value.
type metricWant struct {
	name   string
	labels map[string]string
	value  float64
}

// moduleConfig builds the exporter config with one module per probe case.
func moduleConfig(cases []probeCase) (string, error) {
	modules := map[string]any{}
	for _, c := range cases {
		name := c.moduleName()
		if _, ok := modules[name]; ok {
			return "", fmt.Errorf("duplicate module %s", name)
		}
		section := map[string]any{}
		if err := yaml.Unmarshal([]byte(c.module), &section); err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		if _, ok := section["preferred_ip_protocol"]; !ok {
			section["preferred_ip_protocol"] = "ip4"
		}
		modules[name] = map[string]any{"prober": c.prober, "timeout": "5s", c.prober: section}
	}
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	// 2 spaces, so TestReload can append modules as text.
	enc.SetIndent(2)
	if err := enc.Encode(map[string]any{"modules": modules}); err != nil {
		return "", err
	}
	return b.String(), nil
}

// probeResult is one /probe?debug=true response.
type probeResult struct {
	logs    string
	metrics map[string]*dto.MetricFamily
}

// probe calls /probe with debug=true, which returns the probe logs and the metrics in one response.
func probe(t *testing.T, module, target string) probeResult {
	t.Helper()
	q := url.Values{"module": {module}, "target": {target}, "debug": {"true"}}
	body := mustGet(t, exporterURL+"/probe?"+q.Encode())
	logs, rest, ok := strings.Cut(body, "Metrics that would have been returned:\n")
	if !ok {
		t.Fatalf("unexpected debug output:\n%s", body)
	}
	text, _, _ := strings.Cut(rest, "\n\n\nModule configuration:")
	p := expfmt.NewTextParser(model.UTF8Validation)
	metrics, err := p.TextToMetricFamilies(strings.NewReader(text))
	if err != nil {
		t.Fatalf("parse metrics: %v\n%s", err, text)
	}
	return probeResult{logs: logs, metrics: metrics}
}

// value returns the value of the first series of name whose labels include labels.
func (r probeResult) value(name string, labels map[string]string) (float64, bool) {
	mf, ok := r.metrics[name]
	if !ok {
		return 0, false
	}
	for _, m := range mf.GetMetric() {
		if hasLabels(m, labels) {
			switch {
			case m.GetGauge() != nil:
				return m.GetGauge().GetValue(), true
			case m.GetCounter() != nil:
				return m.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}

func hasLabels(m *dto.Metric, want map[string]string) bool {
	got := map[string]string{}
	for _, lp := range m.GetLabel() {
		got[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// wantSuccess probes once and fails the test unless probe_success is want.
func wantSuccess(t *testing.T, module, target string, want float64) {
	t.Helper()
	r := probe(t, module, target)
	if got, _ := r.value("probe_success", nil); got != want {
		t.Fatalf("%s %s: probe_success = %v, want %v\nlogs:\n%s", module, target, got, want, r.logs)
	}
}

// waitFor polls fn until it returns nil or the deadline passes.
func waitFor(d time.Duration, fn func() error) error {
	deadline := time.Now().Add(d)
	for {
		err := fn()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func get(c *http.Client, u string) (int, string, error) {
	resp, err := c.Get(u)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), err
}

func mustGet(t *testing.T, u string) string {
	t.Helper()
	code, body, err := get(httpClient, u)
	if err != nil || code != http.StatusOK {
		t.Fatalf("GET %s: %d %v\n%s", u, code, err, body)
	}
	return body
}

// writeCerts writes a self-signed cert for the exporter's own TLS in TestWebConfig.
func writeCerts(dir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "blackbox"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(48 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "server.crt"), "CERTIFICATE", der); err != nil {
		return err
	}
	return writePEM(filepath.Join(dir, "server.key"), "PRIVATE KEY", keyDER)
}

func writePEM(path, typ string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o644)
}
