# Local end-to-end example

A docker compose stack that builds blackbox_exporter from this checkout and probes local targets for every main prober (HTTP, HTTPS, TCP, TLS, SMTP STARTTLS, DNS, websocket, ICMP, gRPC). Every probe targets a service on the compose network. Internet access is only needed to pull images and Go modules on the first build. Use it to check probe behaviour by hand, from an agent, or in CI.

Beyond plain reachability, cases cover HTTP basic auth, `fail_if_ssl` and `fail_if_not_ssl` (including a redirect to HTTPS), `valid_status_codes` with a 404, header and CEL JSON body matching, client certificate mTLS, TCP `query_response` against a line echo server, DNS over TLS, `validate_answer_rrs` and gRPC health checks. Most come with a negative case that expects `probe_success 0`.

## Usage

```sh
cd examples/local
./test.sh                  # build, start, run every case
./test.sh --no-up          # reuse a stack started with: docker compose up -d --build --wait
docker compose down -v     # tear down, including the generated certs
```

`make e2e-local` from the repo root runs `./test.sh`. The stack keeps running after the tests, so tear it down when you are done.

`test.sh` runs `--config.check` on `examples/local/blackbox.yml`, `example.yml` and `blackbox.yml` inside the built image, then calls `/probe` for each case and compares `probe_success` with the expected value. It prints one `PASS` or `FAIL` line per case and exits non-zero if any case fails. Failing cases also print the probe's error log lines.

The exporter listens on `127.0.0.1:9115` (override with `BLACKBOX_PORT`), so you can probe by hand:

```sh
curl 'http://127.0.0.1:9115/probe?module=dns_udp_example&target=dns:53&debug=true'
```

## Services

| Service     | Image                         | Used by                                                              |
|-------------|-------------------------------|----------------------------------------------------------------------|
| `blackbox`  | built from `Dockerfile`       | the exporter, with `NET_RAW` for ICMP                                |
| `certs`     | `alpine/openssl:3.5.4`        | one-shot, runs `certs/gen.sh` to create a CA, server and client cert |
| `web`       | `nginx:1.29-alpine`           | HTTP on 80, HTTPS on 443, TCP, TLS and ICMP targets, mTLS on 8443    |
| `mail`      | `axllent/mailpit:v1.27`       | SMTP with STARTTLS on 1025                                           |
| `dns`       | `coredns/coredns:1.12.4`      | `local.test` zone from `coredns/`, DoT on 853                        |
| `websocket` | `jmalloc/echo-server:v0.3.7`  | websocket echo on 8080                                               |
| `echo`      | `busybox:1.37`                | line echo on TCP 7 for `query_response`                              |
| `grpc`      | `quay.io/coreos/etcd:v3.5.21` | gRPC health service on 2379                                          |

The certs are regenerated on each fresh `certs` volume and are trusted only through `ca_file: /certs/ca.crt` in `blackbox.yml`.

## Adding a case

1. Add a module to `blackbox.yml`. Reuse the module name from the repo's `example.yml` when one fits.
2. If it needs a new target, add a service with a pinned image tag to `compose.yaml`.
3. Add a `module target expected_probe_success` line to `CASES` at the top of `test.sh`. Add a negative case (expected `0`) when the module has a failure condition worth proving.
4. Run `./test.sh`. Config changes are picked up with `curl -X POST http://127.0.0.1:9115/-/reload`.
