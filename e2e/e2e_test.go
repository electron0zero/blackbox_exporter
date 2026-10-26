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

// Package e2e runs the exporter image against badserver in docker compose.
// Run it with `make test-e2e`. Set E2E_KEEP=1 to leave the stack running afterwards.
package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var (
	// exporterURL is the exporter with the config from moduleConfig.
	exporterURL string
	// badserverURL is badserver's HTTP port, for reading what its proxy saw.
	badserverURL string
	runDir       string
	httpClient   = &http.Client{Timeout: 30 * time.Second}
)

// webConfig is the exporter's own TLS and basic auth. The password is e2e-password.
const webConfig = `
tls_server_config:
  cert_file: /certs/server.crt
  key_file: /certs/server.key
basic_auth_users:
  e2e: $2b$10$kimYjAhxinmKBC6LBqom7edXSuODxDVVaUvfccJ6iKAdK6ziEIg/a
`

func TestMain(m *testing.M) {
	code, err := run(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		if out, _ := compose("logs", "--no-color", "--tail=50"); out != "" {
			fmt.Fprintln(os.Stderr, out)
		}
		code = 1
	}
	if os.Getenv("E2E_KEEP") == "" {
		compose("down", "-v", "--remove-orphans")
		os.RemoveAll(runDir)
	}
	os.Exit(code)
}

func run(m *testing.M) (int, error) {
	var err error
	if runDir, err = os.MkdirTemp("", "bbe-e2e-"); err != nil {
		return 0, err
	}
	for _, d := range []string{"config", "certs"} {
		if err := os.Mkdir(filepath.Join(runDir, d), 0o755); err != nil {
			return 0, err
		}
	}
	cfg, err := moduleConfig(probeCases)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(runDir, "config", "blackbox.yml"), []byte(cfg), 0o644); err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(runDir, "config", "web-config.yml"), []byte(webConfig), 0o644); err != nil {
		return 0, err
	}
	if err := writeCerts(filepath.Join(runDir, "certs")); err != nil {
		return 0, err
	}

	// The root Dockerfile copies the binary from .build/linux-<arch>, as promu crossbuild lays it out.
	exporterBin := filepath.Join("..", ".build", "linux-"+runtime.GOARCH, "blackbox_exporter")
	if err := goBuild(exporterBin, ".."); err != nil {
		return 0, err
	}
	if err := goBuild(filepath.Join(runDir, "badserver"), "./badserver"); err != nil {
		return 0, err
	}

	os.Setenv("E2E_RUN_DIR", runDir)
	os.Setenv("E2E_ARCH", runtime.GOARCH)
	if out, err := compose("up", "-d", "--build", "--wait", "--quiet-pull"); err != nil {
		return 0, fmt.Errorf("compose up: %w\n%s", err, out)
	}
	if exporterURL, err = hostURL("blackbox", "9115", "http"); err != nil {
		return 0, err
	}
	if badserverURL, err = hostURL("badserver", "8080", "http"); err != nil {
		return 0, err
	}
	return m.Run(), nil
}

func goBuild(out, pkg string) error {
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s: %w\n%s", pkg, err, b)
	}
	return nil
}

// hostURL returns the host address compose published for the service's port.
func hostURL(service, port, scheme string) (string, error) {
	out, err := compose("port", service, port)
	if err != nil {
		return "", fmt.Errorf("compose port %s: %w\n%s", service, err, out)
	}
	return scheme + "://" + strings.TrimSpace(out), nil
}

func TestReload(t *testing.T) {
	path := filepath.Join(runDir, "config", "blackbox.yml")
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.WriteFile(path, orig, 0o644)
		httpClient.Post(exporterURL+"/-/reload", "", nil)
	})

	reload := func() (int, string) {
		resp, err := httpClient.Post(exporterURL+"/-/reload", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	added := string(orig) + "  http_reloaded:\n    prober: http\n    timeout: 5s\n    http:\n      preferred_ip_protocol: ip4\n"
	if err := os.WriteFile(path, []byte(added), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, body := reload(); code != http.StatusOK {
		t.Fatalf("reload of a valid config: %d %s", code, body)
	}
	wantSuccess(t, "http_reloaded", httpOK, 1)

	if err := os.WriteFile(path, []byte(added+"  broken:\n    prober: nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _ := reload(); code != http.StatusInternalServerError {
		t.Fatalf("reload of a broken config: status %d, want 500", code)
	}
	wantSuccess(t, "http_reloaded", httpOK, 1)
	if !strings.Contains(mustGet(t, exporterURL+"/metrics"), "blackbox_exporter_config_last_reload_successful 0") {
		t.Error("blackbox_exporter_config_last_reload_successful is not 0 after a failed reload")
	}
}

func TestLogsByTarget(t *testing.T) {
	target := httpOK + "/?logs-by-target"
	probe(t, "http_smoke", target)
	body := mustGet(t, exporterURL+"/logs?"+url.Values{"target": {target}}.Encode())
	if !strings.Contains(body, "Beginning probe") {
		t.Fatalf("/logs?target= has no probe log:\n%s", body)
	}
}

func TestWebConfig(t *testing.T) {
	out, err := compose("run", "-d", "--rm", "--no-deps", "-p", "127.0.0.1::9115", "blackbox",
		"--config.file=/config/blackbox.yml", "--web.config.file=/config/web-config.yml")
	if err != nil {
		t.Fatalf("start exporter with web config: %v\n%s", err, out)
	}
	// The container name is the last line, after any compose warnings.
	fields := strings.Fields(out)
	name := fields[len(fields)-1]
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	port, err := exec.Command("docker", "port", name, "9115").Output()
	if err != nil {
		t.Fatalf("docker port %s: %v", name, err)
	}
	authURL := "https://" + strings.TrimSpace(strings.Split(string(port), "\n")[0])

	cert, err := os.ReadFile(filepath.Join(runDir, "certs", "server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cert)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	var code int
	if err := waitFor(30*time.Second, func() error {
		code, _, err = get(c, authURL+"/-/healthy")
		return err
	}); err != nil {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		t.Fatalf("%v\n%s", err, logs)
	}
	if code != http.StatusUnauthorized {
		t.Errorf("without credentials: status %d, want 401", code)
	}

	req, _ := http.NewRequest(http.MethodGet, authURL+"/-/healthy", nil)
	req.SetBasicAuth("e2e", "e2e-password")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("with credentials: status %d, want 200", resp.StatusCode)
	}
}
