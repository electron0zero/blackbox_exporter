# Troubleshooting

Answers to the most common probe questions. For every configuration field see
[CONFIGURATION.md](../CONFIGURATION.md).

## Debug a single probe

Add `&debug=true` to the probe URL to get the probe logs, the metrics that
would have been returned and the module configuration as plain text:

    curl 'http://localhost:9115/probe?target=prometheus.io&module=http_2xx&debug=true'

The logs only contain lines at or above `--log.prober`, which defaults to
`info`. Start the exporter with `--log.prober=debug` to see the `Debug` lines,
such as the resolved IP address and each HTTP request.

## Look at a past probe

The exporter keeps the debug output of the last `--history.limit` probes
(default 100), plus up to `--history.limit` older failed probes. The front page
`/` lists them. Fetch one with `/logs?id=<id>`.
`/logs?target=<target>&module=<module>` returns the oldest kept probe for that
target and module, not the newest. `module` is optional.

## IPv4 or IPv6

`preferred_ip_protocol` defaults to `ip6`. With `ip_protocol_fallback: true`
(the default when the module has a block for its prober) the exporter uses an
IPv4 address only when the target has no IPv6 address. Only one address is
tried. If the host has no working IPv6
route, set `preferred_ip_protocol: ip4`, or also set
`ip_protocol_fallback: false` to use only IPv4. See
[Address selection](../CONFIGURATION.md#address-selection).

## Redirects, Host header and SNI

The first HTTP request goes to the resolved IP with the `Host` header set to
the target host, or to a `Host` header from the module. TLS SNI is
`tls_config.server_name`, else the `Host` header, else the target host. A
redirect whose host differs from the first request's host, which is the
resolved IP, is sent without that `server_name`, so SNI comes from the redirect
URL. Only the first request uses `preferred_ip_protocol`. Set
`follow_redirects: false` to check one hop at a time.

## ICMP permissions

On Linux the exporter first tries an unprivileged ICMP socket, which needs the
process group inside `net.ipv4.ping_group_range`, and then falls back to a raw
socket, which needs `CAP_NET_RAW` or root. `dont_fragment: true` on IPv4
always needs a raw socket. In Docker use `--sysctl net.ipv4.ping_group_range="0 2147483647"`
or `--cap-add NET_RAW`. In Kubernetes set the same sysctl in the pod
`securityContext.sysctls`, or add `NET_RAW` to the container
`securityContext.capabilities`. See [Permissions](../README.md#permissions).

## Timeouts

The probe timeout is the `X-Prometheus-Scrape-Timeout-Seconds` header that
Prometheus sends, minus `--timeout-offset` (default 0.5). Without the header,
or with a header of 0, it is 120 minus the offset, so 119.5 seconds. A module
`timeout` that is set and lower replaces it. When the header minus the offset
is negative, the module `timeout` is used even if it is larger, or 0 when the
module sets none. `probe_timeout_seconds` reports the timeout that
was used, so `probe_duration_seconds / probe_timeout_seconds` shows how close a
probe came to it.

## TLS certificate expiry metrics

`probe_ssl_earliest_cert_expiry` is the earliest `NotAfter` of every
certificate the server sent, intermediates included, not only the leaf.
`probe_ssl_last_chain_expiry_timestamp_seconds` takes the earliest expiry in
each verified chain and reports the latest of those. With
`insecure_skip_verify: true` there is no verified chain and it reports
`-62135596800`. For `http` both describe the final response after redirects.

## query_response

Each `expect` reads lines until one matches the regular expression, skipping
the lines that do not. The match is per line, so a regular expression cannot
span lines. Each `send` writes the text followed by `\n`, not `\r\n`. If the
server needs CRLF, end the text with `\r` in a double-quoted YAML string, for
example `send: "QUIT\r"`. See
[`<tcp_probe>`](../CONFIGURATION.md#tcp_probe).
