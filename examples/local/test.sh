#!/bin/sh
# Probes every module in blackbox.yml against its local target and checks probe_success.
#
# Usage: ./test.sh [--no-up]
#   --no-up  assume the stack is already running instead of building and starting it
set -eu

# module target expected_probe_success
CASES='
http_2xx               http://web              1
http_2xx_body_mismatch http://web              0
http_2xx_tls           https://web             1
tls_connect            web:443                 1
tls_connect_untrusted  web:443                 0
tcp_connect_example    web:80                  1
smtp_starttls          mail:1025               1
dns_udp_example        dns:53                  1
dns_tcp_example        dns:53                  1
dns_nxdomain           dns:53                  0
websocket_example      ws://websocket:8080/    1
icmp_example           web                     1
http_basic_auth        http://web/auth         1
http_basic_auth_wrong_password http://web/auth 0
http_2xx_tls           http://web/to-https     1
http_2xx_tls           http://web              0
http_fail_if_ssl       http://web              1
http_fail_if_ssl       https://web             0
http_404               http://web/missing      1
http_2xx               http://web/missing      0
http_header_match      http://web              1
http_header_mismatch   http://web              0
http_json_cel          http://web/status.json  1
http_json_cel_mismatch http://web/status.json  0
http_mtls              https://web:8443        1
http_2xx_tls           https://web:8443        0
tcp_echo               echo:7                  1
tcp_echo_mismatch      echo:7                  0
dns_over_tls           dns:853                 1
dns_over_tls_untrusted dns:853                 0
dns_answer_mismatch    dns:53                  0
grpc_plain             grpc:2379               1
grpc_unknown_service   grpc:2379               0
'

cd "$(dirname "$0")"

port="${BLACKBOX_PORT:-9115}"
base="http://127.0.0.1:${port}"
up=1

for arg in "$@"; do
  case "${arg}" in
    --no-up) up=0 ;;
    *) echo "unknown flag: ${arg}" >&2; exit 2 ;;
  esac
done

if [ "${up}" -eq 1 ]; then
  docker compose up -d --build --wait
fi

i=0
until curl -fs "${base}/-/healthy" >/dev/null; do
  i=$((i + 1))
  if [ "${i}" -ge 30 ]; then
    echo "blackbox_exporter not healthy at ${base}" >&2
    exit 1
  fi
  sleep 1
done

failed=0

for cfg in examples/local/blackbox.yml example.yml blackbox.yml; do
  if docker compose run --rm --no-deps -T -v "$(pwd)/../../${cfg}:/check.yml:ro" \
    blackbox --config.check --config.file=/check.yml >/dev/null 2>&1; then
    echo "PASS config.check ${cfg}"
  else
    echo "FAIL config.check ${cfg}"
    failed=$((failed + 1))
  fi
done

# Heredoc keeps the loop in this shell so failed survives it.
while read -r module target want; do
  [ -n "${module}" ] || continue
  got=$(curl -s --max-time 15 -G "${base}/probe" \
    --data-urlencode "module=${module}" --data-urlencode "target=${target}" |
    sed -n 's/^probe_success //p')
  if [ "${got}" = "${want}" ]; then
    echo "PASS ${module} ${target} probe_success=${got}"
  else
    echo "FAIL ${module} ${target} want=${want} got=${got:-none}"
    curl -s --max-time 15 -G "${base}/probe" --data-urlencode "debug=true" \
      --data-urlencode "module=${module}" --data-urlencode "target=${target}" |
      grep 'level=ERROR' >&2 || true
    failed=$((failed + 1))
  fi
done <<EOF2
${CASES}
EOF2

if [ "${failed}" -ne 0 ]; then
  echo "${failed} case(s) failed" >&2
  exit 1
fi
echo "all cases passed"
