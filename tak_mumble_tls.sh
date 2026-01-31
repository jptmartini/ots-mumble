#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# TAK / Mumble TLS General Script
#
# Purpose:
#   Configure TLS for a Mumble (mumble-server / Murmur) instance by:
#     - generating or obtaining a server certificate (with correct SANs)
#     - installing the cert/key into /etc/mumble
#     - updating /etc/mumble/mumble-server.ini (sslCert/sslKey/port)
#     - restarting the mumble-server service
#
# Supported modes:
#   1) ots-ca        Use an existing OpenTAKServer CA to sign a server cert
#   2) self-ca       Create a local CA and sign a server cert
#   3) letsencrypt   Obtain a public cert via Certbot + install renewal hook
#
# Notes:
#   - Let's Encrypt does NOT issue certificates for IP addresses, only DNS names.
#   - Clients must connect using an identifier that matches SAN:
#       * Connect via IP  -> SAN must include IP:<ip>
#       * Connect via DNS -> SAN must include DNS:<fqdn>
# ============================================================

# ---------- Defaults ----------
MUMBLE_DIR="/etc/mumble"
CONF="/etc/mumble/mumble-server.ini"
SERVICE="mumble-server"
DEFAULT_PORT="64738"

MODE=""
IP_ADDR=""
FQDN=""
PORT="$DEFAULT_PORT"

# OTS CA defaults (OpenTAKServer)
OTS_CA_DIR="/home/ubuntu/ots/ca"

# Self-CA defaults
SELF_CA_DIR="/etc/mumble/ca"

# Let's Encrypt defaults
LE_EMAIL=""
LE_CHALLENGE="http"          # http or dns
LE_STANDALONE_PORT="80"      # used for certbot --standalone

# ---------- CLI / help ----------
usage() {
  cat <<EOF
Usage:
  sudo $0 --mode <ots-ca|self-ca|letsencrypt> [options]

Common options:
  --ip <IPv4>              Server IP (added to SAN as IP:<ip>)
  --fqdn <name>            Server FQDN (added to SAN as DNS:<fqdn>)
  --port <port>            Mumble port in ini (default: ${DEFAULT_PORT})

Mode: ots-ca
  --ots-ca-dir <path>      OTS CA directory (default: ${OTS_CA_DIR})
    expects:
      ca-do-not-share.key
      ca-trusted.pem (preferred) OR ca.pem

Mode: self-ca
  --self-ca-dir <path>     Directory to store the generated local CA (default: ${SELF_CA_DIR})

Mode: letsencrypt
  --email <email>          Required for certbot registration
  --challenge <http|dns>   http requires inbound TCP :80; dns requires TXT record creation
  --standalone-port <port> Certbot standalone port (default: 80)

Examples:
  # Lab / IP only (OpenTAKServer CA)
  sudo $0 --mode ots-ca --ip 192.168.0.14

  # Lab / FQDN + IP (OpenTAKServer CA)
  sudo $0 --mode ots-ca --fqdn mumble.lab.local --ip 192.168.0.14

  # Public FQDN (Let's Encrypt via HTTP-01)
  sudo $0 --mode letsencrypt --fqdn voice.example.com --email admin@example.com --challenge http

EOF
}

# ---------- Helpers ----------
require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run as root (use sudo)."
    exit 1
  fi
}

require_file() {
  [[ -f "$1" ]] || { echo "ERROR: Missing file: $1"; exit 1; }
}

ensure_pkg() {
  local bin="$1"
  local pkg="$2"
  command -v "$bin" >/dev/null 2>&1 || {
    apt-get update -y
    apt-get install -y "$pkg"
  }
}

is_valid_ip() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    ((o >= 0 && o <= 255)) || return 1
  done
  return 0
}

ensure_mumble_paths() {
  mkdir -p "$MUMBLE_DIR"
  [[ -f "$CONF" ]] || touch "$CONF"
}

# Set or add key=value in the ini file
set_ini_kv() {
  local key="$1"
  local val="$2"
  if grep -q "^${key}=" "$CONF"; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$CONF"
  else
    echo "${key}=${val}" >> "$CONF"
  fi
}

print_relevant_ini() {
  echo "Current relevant INI settings:"
  grep -nE '^(sslCert|sslKey|port)=' "$CONF" || true
}

restart_mumble() {
  # Prefer a direct restart; do not hard-fail if systemd is not present (containers etc.)
  if systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE}\.service"; then
    systemctl restart "$SERVICE"
  else
    echo "WARNING: systemd unit ${SERVICE}.service not found. Restart manually if required."
  fi
}

# ---------- OpenSSL server cert creation ----------
# Arguments:
#   ca_key ca_cert out_dir common_name san_csv
# Example san_csv:
#   DNS:voice.example.com,IP:192.168.0.14
openssl_make_server_cert() {
  local ca_key="$1"
  local ca_cert="$2"
  local out_dir="$3"
  local cn="$4"
  local san_csv="$5"

  mkdir -p "$out_dir"

  local key="${out_dir}/server.key"
  local csr="${out_dir}/server.csr"
  local crt="${out_dir}/server.crt"
  local chain="${out_dir}/server_chain.crt"
  local ext="${out_dir}/server_ext.cnf"

  echo "Generating server key/CSR (CN=${cn})..."
  openssl genrsa -out "$key" 4096
  openssl req -new -key "$key" -out "$csr" -subj "/CN=${cn}"

  echo "Writing SAN extension: ${san_csv}"
  cat > "$ext" <<EOF
subjectAltName = ${san_csv}
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = serverAuth
EOF

  echo "Signing server certificate..."
  openssl x509 -req -in "$csr" \
    -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
    -out "$crt" -days 825 -sha256 -extfile "$ext"

  # Chain file for services that expect leaf+CA together
  cat "$crt" "$ca_cert" > "$chain"

  echo "Created:"
  echo "  ${key}"
  echo "  ${crt}"
  echo "  ${chain}"
}

# ---------- Mode: ots-ca ----------
mode_ots_ca() {
  ensure_pkg openssl openssl
  ensure_mumble_paths

  local ca_key="${OTS_CA_DIR}/ca-do-not-share.key"
  local ca_cert="${OTS_CA_DIR}/ca-trusted.pem"
  [[ -f "$ca_cert" ]] || ca_cert="${OTS_CA_DIR}/ca.pem"

  require_file "$ca_key"
  require_file "$ca_cert"

  # Build SAN list
  local san_parts=()
  [[ -n "$FQDN" ]] && san_parts+=("DNS:${FQDN}")
  [[ -n "$IP_ADDR" ]] && san_parts+=("IP:${IP_ADDR}")

  if [[ ${#san_parts[@]} -eq 0 ]]; then
    echo "ERROR: Provide --ip and/or --fqdn so we can build SAN entries."
    exit 1
  fi

  local san_csv
  san_csv="$(IFS=,; echo "${san_parts[*]}")"

  # Prefer CN = FQDN if provided, otherwise IP
  local cn="${FQDN:-$IP_ADDR}"
  local out_dir="${MUMBLE_DIR}/tls"

  openssl_make_server_cert "$ca_key" "$ca_cert" "$out_dir" "$cn" "$san_csv"

  # Install into /etc/mumble
  install -m 640 "${out_dir}/server.key" "${MUMBLE_DIR}/server.key"
  install -m 644 "${out_dir}/server.crt" "${MUMBLE_DIR}/server.crt"
  install -m 644 "${out_dir}/server_chain.crt" "${MUMBLE_DIR}/server_chain.crt"
  install -m 644 "$ca_cert" "${MUMBLE_DIR}/ca.pem"

  # Ensure the service user can read the private key.
  # On Ubuntu, mumble-server typically runs as user/group "mumble-server".
  chown root:mumble-server "${MUMBLE_DIR}/server.key" 2>/dev/null || true
  chmod 640 "${MUMBLE_DIR}/server.key" || true

  set_ini_kv "port" "$PORT"
  set_ini_kv "sslCert" "${MUMBLE_DIR}/server_chain.crt"
  set_ini_kv "sslKey"  "${MUMBLE_DIR}/server.key"

  print_relevant_ini
  restart_mumble

  echo
  echo "Verification command (uses OTS CA as trust anchor):"
  echo "  openssl s_client -connect ${IP_ADDR:-127.0.0.1}:${PORT} -servername ${FQDN:-${IP_ADDR:-127.0.0.1}} -CAfile ${ca_cert} </dev/null | openssl x509 -noout -subject -issuer -dates"
}

# ---------- Mode: self-ca ----------
mode_self_ca() {
  ensure_pkg openssl openssl
  ensure_mumble_paths

  mkdir -p "$SELF_CA_DIR"
  local ca_key="${SELF_CA_DIR}/ca.key"
  local ca_crt="${SELF_CA_DIR}/ca.crt"

  if [[ ! -f "$ca_key" || ! -f "$ca_crt" ]]; then
    echo "Creating local CA in ${SELF_CA_DIR}..."
    openssl genrsa -out "$ca_key" 4096
    openssl req -x509 -new -nodes -key "$ca_key" -sha256 -days 3650 \
      -subj "/CN=Local Mumble CA" -out "$ca_crt"
  else
    echo "Using existing local CA in ${SELF_CA_DIR}."
  fi

  local san_parts=()
  [[ -n "$FQDN" ]] && san_parts+=("DNS:${FQDN}")
  [[ -n "$IP_ADDR" ]] && san_parts+=("IP:${IP_ADDR}")

  if [[ ${#san_parts[@]} -eq 0 ]]; then
    echo "ERROR: Provide --ip and/or --fqdn so we can build SAN entries."
    exit 1
  fi

  local san_csv
  san_csv="$(IFS=,; echo "${san_parts[*]}")"

  local cn="${FQDN:-$IP_ADDR}"
  local out_dir="${MUMBLE_DIR}/tls"

  openssl_make_server_cert "$ca_key" "$ca_crt" "$out_dir" "$cn" "$san_csv"

  install -m 640 "${out_dir}/server.key" "${MUMBLE_DIR}/server.key"
  install -m 644 "${out_dir}/server.crt" "${MUMBLE_DIR}/server.crt"
  install -m 644 "${out_dir}/server_chain.crt" "${MUMBLE_DIR}/server_chain.crt"
  install -m 644 "$ca_crt" "${MUMBLE_DIR}/ca.pem"

  chown root:mumble-server "${MUMBLE_DIR}/server.key" 2>/dev/null || true
  chmod 640 "${MUMBLE_DIR}/server.key" || true

  set_ini_kv "port" "$PORT"
  set_ini_kv "sslCert" "${MUMBLE_DIR}/server_chain.crt"
  set_ini_kv "sslKey"  "${MUMBLE_DIR}/server.key"

  print_relevant_ini
  restart_mumble

  echo
  echo "Distribute this CA certificate to clients (trust store):"
  echo "  ${ca_crt}"
}

# ---------- Mode: letsencrypt ----------
mode_letsencrypt() {
  ensure_pkg openssl openssl
  ensure_pkg certbot certbot
  ensure_mumble_paths

  if [[ -z "$FQDN" ]]; then
    echo "ERROR: Let's Encrypt requires --fqdn (LE does not issue IP certificates)."
    exit 1
  fi
  if [[ -z "$LE_EMAIL" ]]; then
    echo "ERROR: Let's Encrypt requires --email."
    exit 1
  fi
  if [[ "$LE_CHALLENGE" != "http" && "$LE_CHALLENGE" != "dns" ]]; then
    echo "ERROR: --challenge must be http or dns"
    exit 1
  fi

  echo "Requesting Let's Encrypt certificate for: ${FQDN}"
  if [[ "$LE_CHALLENGE" == "http" ]]; then
    echo "HTTP-01 challenge selected: inbound TCP :${LE_STANDALONE_PORT} must reach this host."
    certbot certonly --standalone \
      --preferred-challenges http \
      --http-01-port "$LE_STANDALONE_PORT" \
      -d "$FQDN" \
      --agree-tos -m "$LE_EMAIL" --non-interactive
  else
    echo "DNS-01 challenge selected: you will be prompted to create TXT records."
    certbot certonly --manual \
      --preferred-challenges dns \
      -d "$FQDN" \
      --agree-tos -m "$LE_EMAIL" --non-interactive
  fi

  local live="/etc/letsencrypt/live/${FQDN}"
  require_file "${live}/fullchain.pem"
  require_file "${live}/privkey.pem"

  # Copy cert/key into /etc/mumble with permissions that allow the mumble-server user to read the key.
  echo "Installing Let's Encrypt cert/key into ${MUMBLE_DIR}..."
  install -m 644 "${live}/fullchain.pem" "${MUMBLE_DIR}/server_chain.crt"
  install -m 640 "${live}/privkey.pem"   "${MUMBLE_DIR}/server.key"

  chown root:mumble-server "${MUMBLE_DIR}/server.key" 2>/dev/null || true
  chmod 640 "${MUMBLE_DIR}/server.key" || true

  set_ini_kv "port" "$PORT"
  set_ini_kv "sslCert" "${MUMBLE_DIR}/server_chain.crt"
  set_ini_kv "sslKey"  "${MUMBLE_DIR}/server.key"

  print_relevant_ini
  restart_mumble

  # Create a certbot deploy hook so renewals automatically re-copy and restart mumble-server.
  local hook="/etc/letsencrypt/renewal-hooks/deploy/mumble-server.sh"
  echo "Creating certbot deploy hook: ${hook}"
  cat > "$hook" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# Called by certbot after renewals.
# Uses $RENEWED_LINEAGE to find the renewed cert material.
SRC_CHAIN="${RENEWED_LINEAGE}/fullchain.pem"
SRC_KEY="${RENEWED_LINEAGE}/privkey.pem"

DEST_DIR="/etc/mumble"
DEST_CHAIN="${DEST_DIR}/server_chain.crt"
DEST_KEY="${DEST_DIR}/server.key"

install -m 644 "$SRC_CHAIN" "$DEST_CHAIN"
install -m 640 "$SRC_KEY"   "$DEST_KEY"

chown root:mumble-server "$DEST_KEY" 2>/dev/null || true
chmod 640 "$DEST_KEY" || true

systemctl restart mumble-server || true
EOF
  chmod +x "$hook"

  echo
  echo "Done. Future renewals will redeploy and restart mumble-server automatically."
}

# ---------- Parse arguments ----------
[[ $# -eq 0 ]] && { usage; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --ip) IP_ADDR="${2:-}"; shift 2 ;;
    --fqdn) FQDN="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --ots-ca-dir) OTS_CA_DIR="${2:-}"; shift 2 ;;
    --self-ca-dir) SELF_CA_DIR="${2:-}"; shift 2 ;;
    --email) LE_EMAIL="${2:-}"; shift 2 ;;
    --challenge) LE_CHALLENGE="${2:-}"; shift 2 ;;
    --standalone-port) LE_STANDALONE_PORT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: Unknown argument: $1"; usage; exit 1 ;;
  esac
done

require_root

# Validate IP if provided
if [[ -n "$IP_ADDR" ]]; then
  is_valid_ip "$IP_ADDR" || { echo "ERROR: Invalid IP: $IP_ADDR"; exit 1; }
fi

case "$MODE" in
  ots-ca) mode_ots_ca ;;
  self-ca) mode_self_ca ;;
  letsencrypt) mode_letsencrypt ;;
  *) echo "ERROR: Invalid --mode: $MODE"; usage; exit 1 ;;
esac
