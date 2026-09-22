#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# BF3 rshim bootstrap using SSH KEYS ONLY (no passwords / no expect / no sshpass)
#
# Supports:
#   --mode ipv6   : IPv6 forwarding + NAT66 + BF IPv6 + DNS via host (dnsmasq->127.0.0.53)
#   --mode ipv4   : IPv4 forwarding + NAT44 + BF IPv4 + DNS via host (dnsmasq->127.0.0.53)
#   --mode dual   : Both ipv6 + ipv4
#
# Key behavior (important):
#   - Script runs with sudo, but SSH to BF is executed as the invoking user ($SUDO_USER),
#     explicitly using that user's ~/.ssh/id_ed25519 key.
#   - SSH is forced to be key-only (BatchMode=yes, PasswordAuthentication=no).
#
# Assumptions:
#   - You have already run (as your normal user):
#       ssh-copy-id -i ~/.ssh/id_ed25519 ubuntu@192.168.100.2
#
# Usage:
#   sudo ./bf3_rshim_bootstrap_keyonly.sh --mode ipv6
#   sudo ./bf3_rshim_bootstrap_keyonly.sh --mode ipv4
#   sudo ./bf3_rshim_bootstrap_keyonly.sh --mode dual
#   sudo ./bf3_rshim_bootstrap_keyonly.sh --mode dual --bfb /opt/bf-bundle/whatever.bfb
# =============================================================================

# ---- Defaults (override via args) ----
MODE="ipv6"                    # ipv6 | ipv4 | dual
HOST_TMFIFO_IF="tmfifo_net0"

HOST_V4_ADDR="192.168.100.1/24"
HOST_V4_IP="192.168.100.1"
BF_V4_ADDR="192.168.100.2/24"
BF_V4_IP="192.168.100.2"

PREFIX_V6="fd00:bf3::/64"
HOST_V6_ADDR="fd00:bf3::1/64"
HOST_V6_IP="fd00:bf3::1"
BF_V6_ADDR="fd00:bf3::2/64"
BF_V6_IP="fd00:bf3::2"

BF_SSH_USER="ubuntu"
BF_SSH_HOST="192.168.100.2"

BFB_PATH=""
DO_INSTALL_PKGS=1

log() { echo "[$(date +'%F %T')] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root (use sudo)."
}

need_mode_valid() {
  case "${MODE}" in
    ipv4|ipv6|dual) ;;
    *) die "--mode must be one of: ipv4 | ipv6 | dual" ;;
  esac
}

default_v6_iface() {
  local iface
  iface="$(ip -6 route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  [[ -n "${iface}" ]] || die "No host IPv6 default route found; required for --mode ipv6/dual."
  echo "${iface}"
}

default_v4_iface() {
  local iface
  iface="$(ip route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  [[ -n "${iface}" ]] || die "No host IPv4 default route found; required for --mode ipv4/dual."
  echo "${iface}"
}

# ---- Arg parsing ----
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --host-if) HOST_TMFIFO_IF="$2"; shift 2;;
    --host-v4) HOST_V4_ADDR="$2"; HOST_V4_IP="$(echo "$2" | cut -d/ -f1)"; shift 2;;
    --bf-v4) BF_V4_ADDR="$2"; BF_V4_IP="$(echo "$2" | cut -d/ -f1)"; shift 2;;
    --host-v6) HOST_V6_ADDR="$2"; HOST_V6_IP="$(echo "$2" | cut -d/ -f1)"; shift 2;;
    --prefix-v6) PREFIX_V6="$2"; shift 2;;
    --bf-v6) BF_V6_ADDR="$2"; BF_V6_IP="$(echo "$2" | cut -d/ -f1)"; shift 2;;
    --bf-ssh-user) BF_SSH_USER="$2"; shift 2;;
    --bf-ssh-host) BF_SSH_HOST="$2"; shift 2;;
    --bfb) BFB_PATH="$2"; shift 2;;
    --no-install) DO_INSTALL_PKGS=0; shift 1;;
    -h|--help)
      cat <<EOF
Usage: sudo $0 [options]

Required:
  --mode <ipv6|ipv4|dual>    (default: ipv6)

Host:
  --host-if <ifname>         Host tmfifo interface (default: ${HOST_TMFIFO_IF})
  --host-v4 <addr/cidr>      Host IPv4 on tmfifo (default: ${HOST_V4_ADDR})
  --host-v6 <addr/cidr>      Host IPv6 on tmfifo (default: ${HOST_V6_ADDR})
  --prefix-v6 <cidr>         IPv6 prefix (default: ${PREFIX_V6})
  --no-install               Skip apt installs on host

BlueField:
  --bf-v4 <addr/cidr>        BF IPv4 on tmfifo (default: ${BF_V4_ADDR})
  --bf-v6 <addr/cidr>        BF IPv6 on tmfifo (default: ${BF_V6_ADDR})
  --bf-ssh-user <user>       BF SSH user (default: ${BF_SSH_USER})
  --bf-ssh-host <host>       BF SSH host (default: ${BF_SSH_HOST})

Optional:
  --bfb <path>               Run bfb-install with this .bfb (optional)
EOF
      exit 0
      ;;
    *)
      die "Unknown argument: $1"
      ;;
  esac
done

need_root
need_mode_valid

# ---- Determine invoking user + explicit SSH key ----
SSH_USER="${SUDO_USER:-$USER}"
SSH_HOME="$(getent passwd "${SSH_USER}" | cut -d: -f6)"
[[ -n "${SSH_HOME}" ]] || die "Could not determine home for SSH_USER=${SSH_USER}"

SSH_KEY="${SSH_HOME}/.ssh/id_ed25519"
[[ -f "${SSH_KEY}" ]] || die "SSH key not found: ${SSH_KEY} (create it with ssh-keygen and run ssh-copy-id to BF)"

# ---- Install required packages on host ----
if [[ "${DO_INSTALL_PKGS}" -eq 1 ]]; then
  log "Host: installing required packages (iptables, dnsmasq, openssh-client)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null || true
  apt-get install -y iptables dnsmasq openssh-client >/dev/null
fi

# ---- Preflight ----
has_cmd ip || die "Missing 'ip'"
has_cmd iptables || die "Missing 'iptables'"
has_cmd ip6tables || die "Missing 'ip6tables'"
has_cmd dnsmasq || die "Missing 'dnsmasq'"
has_cmd ssh || die "Missing 'ssh'"

# SSH to BF: run as SSH_USER, force key-only, do not write known_hosts
BF_SSH_CMD=(
  sudo -u "${SSH_USER}" -H
  ssh
  -i "${SSH_KEY}"
  -o BatchMode=yes
  -o PasswordAuthentication=no
  -o PreferredAuthentications=publickey
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o GlobalKnownHostsFile=/dev/null
  -o ConnectTimeout=8
)

# Determine egress interfaces
OUT_IF6=""
OUT_IF4=""
if [[ "${MODE}" == "ipv6" || "${MODE}" == "dual" ]]; then
  OUT_IF6="$(default_v6_iface)"
  log "Detected host IPv6 egress interface: ${OUT_IF6}"
fi
if [[ "${MODE}" == "ipv4" || "${MODE}" == "dual" ]]; then
  OUT_IF4="$(default_v4_iface)"
  log "Detected host IPv4 egress interface: ${OUT_IF4}"
fi

# ---- Step 0: bring up rshim (best-effort) ----
log "Host: ensure rshim is running (best-effort)"
modprobe rshim 2>/dev/null || true
systemctl start rshim 2>/dev/null || true

# ---- Step 1: bring up tmfifo_net0 and assign addresses on host ----
log "Host: bring up ${HOST_TMFIFO_IF}"
ip link set "${HOST_TMFIFO_IF}" up || true

if [[ "${MODE}" == "ipv4" || "${MODE}" == "dual" ]]; then
  log "Host: assign IPv4 ${HOST_V4_ADDR} on ${HOST_TMFIFO_IF}"
  if ! ip -4 addr show dev "${HOST_TMFIFO_IF}" | grep -q "${HOST_V4_IP}"; then
    ip addr add "${HOST_V4_ADDR}" dev "${HOST_TMFIFO_IF}"
  else
    log "Host: IPv4 already present on ${HOST_TMFIFO_IF}"
  fi
fi

if [[ "${MODE}" == "ipv6" || "${MODE}" == "dual" ]]; then
  log "Host: assign IPv6 ${HOST_V6_ADDR} on ${HOST_TMFIFO_IF}"
  if ! ip -6 addr show dev "${HOST_TMFIFO_IF}" | grep -q "${HOST_V6_IP}"; then
    ip -6 addr add "${HOST_V6_ADDR}" dev "${HOST_TMFIFO_IF}"
  else
    log "Host: IPv6 already present on ${HOST_TMFIFO_IF}"
  fi
fi

# ---- Step 2: forwarding + NAT on host ----
if [[ "${MODE}" == "ipv6" || "${MODE}" == "dual" ]]; then
  log "Host: enable IPv6 forwarding"
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
  sysctl -w "net.ipv6.conf.${HOST_TMFIFO_IF}.forwarding=1" >/dev/null
  sysctl -w "net.ipv6.conf.${OUT_IF6}.forwarding=1" >/dev/null || true

  log "Host: ensure route for ${PREFIX_V6} via ${HOST_TMFIFO_IF}"
  if ! ip -6 route show | grep -qE "^${PREFIX_V6} .* dev ${HOST_TMFIFO_IF}\b"; then
    ip -6 route add "${PREFIX_V6}" dev "${HOST_TMFIFO_IF}" 2>/dev/null || true
  fi

  log "Host: ip6tables FORWARD allow rules (idempotent)"
  ip6tables -C FORWARD -i "${HOST_TMFIFO_IF}" -o "${OUT_IF6}" -j ACCEPT 2>/dev/null || \
    ip6tables -A FORWARD -i "${HOST_TMFIFO_IF}" -o "${OUT_IF6}" -j ACCEPT
  ip6tables -C FORWARD -i "${OUT_IF6}" -o "${HOST_TMFIFO_IF}" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    ip6tables -A FORWARD -i "${OUT_IF6}" -o "${HOST_TMFIFO_IF}" -m state --state ESTABLISHED,RELATED -j ACCEPT

  log "Host: NAT66 MASQUERADE ${PREFIX_V6} out ${OUT_IF6} (idempotent)"
  ip6tables -t nat -C POSTROUTING -s "${PREFIX_V6}" -o "${OUT_IF6}" -j MASQUERADE 2>/dev/null || \
    ip6tables -t nat -A POSTROUTING -s "${PREFIX_V6}" -o "${OUT_IF6}" -j MASQUERADE
fi

if [[ "${MODE}" == "ipv4" || "${MODE}" == "dual" ]]; then
  log "Host: enable IPv4 forwarding"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  log "Host: iptables FORWARD allow rules (idempotent)"
  iptables -C FORWARD -i "${HOST_TMFIFO_IF}" -o "${OUT_IF4}" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${HOST_TMFIFO_IF}" -o "${OUT_IF4}" -j ACCEPT
  iptables -C FORWARD -i "${OUT_IF4}" -o "${HOST_TMFIFO_IF}" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "${OUT_IF4}" -o "${HOST_TMFIFO_IF}" -m state --state ESTABLISHED,RELATED -j ACCEPT

  log "Host: NAT44 MASQUERADE 192.168.100.0/24 out ${OUT_IF4} (idempotent)"
  iptables -t nat -C POSTROUTING -s 192.168.100.0/24 -o "${OUT_IF4}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o "${OUT_IF4}" -j MASQUERADE
fi

# ---- Step 3: host DNS forwarder for BF (dnsmasq -> 127.0.0.53) ----
log "Host: configure dnsmasq on ${HOST_TMFIFO_IF} to forward to 127.0.0.53"

DNSMASQ_CONF="/etc/dnsmasq.d/bf3-rshim.conf"
{
  echo "# Managed by bf3_rshim_bootstrap_keyonly.sh"
  echo "interface=${HOST_TMFIFO_IF}"
  echo "bind-interfaces"
  if [[ "${MODE}" == "ipv4" || "${MODE}" == "dual" ]]; then
    echo "listen-address=${HOST_V4_IP}"
  fi
  if [[ "${MODE}" == "ipv6" || "${MODE}" == "dual" ]]; then
    echo "listen-address=${HOST_V6_IP}"
  fi
  echo "server=127.0.0.53"
  echo "cache-size=1000"
  echo "neg-ttl=60"
} > "${DNSMASQ_CONF}"

systemctl restart dnsmasq
systemctl enable dnsmasq >/dev/null 2>&1 || true

# ---- Optional: BFB install ----
if [[ -n "${BFB_PATH}" ]]; then
  has_cmd bfb-install || die "bfb-install not found"
  log "Running bfb-install: ${BFB_PATH}"
  bfb-install --bfb "${BFB_PATH}" --rshim rshim0
  log "bfb-install completed (BF may reboot)."
fi

# ---- Preflight: verify key-based SSH to BF ----
log "Preflight: verify key-based SSH to ${BF_SSH_USER}@${BF_SSH_HOST} using ${SSH_KEY} (as ${SSH_USER})"
if ! "${BF_SSH_CMD[@]}" "${BF_SSH_USER}@${BF_SSH_HOST}" "true" >/dev/null 2>&1; then
  die "Key-based SSH failed.
Run (as ${SSH_USER}): ssh-copy-id -i ${SSH_KEY} ${BF_SSH_USER}@${BF_SSH_HOST}"
fi

# ---- Step 4: configure BF networking ----
log "BlueField: configure networking (mode=${MODE}) using SSH keys (no passwords)"

# Build BF /etc/resolv.conf content based on mode
BF_RESOLV_LINES=()
if [[ "${MODE}" == "ipv6" || "${MODE}" == "dual" ]]; then
  BF_RESOLV_LINES+=("nameserver ${HOST_V6_IP}")
fi
if [[ "${MODE}" == "ipv4" || "${MODE}" == "dual" ]]; then
  BF_RESOLV_LINES+=("nameserver ${HOST_V4_IP}")
fi

BF_RESOLV_CONTENT="$(printf "%s\n" "${BF_RESOLV_LINES[@]}")"

"${BF_SSH_CMD[@]}" "${BF_SSH_USER}@${BF_SSH_HOST}" bash -s <<EOF
set -euo pipefail

echo "[BF] Bring up ${HOST_TMFIFO_IF}"
sudo ip link set "${HOST_TMFIFO_IF}" up || true

if [[ "${MODE}" == "ipv4" || "${MODE}" == "dual" ]]; then
  echo "[BF] Ensure IPv4 ${BF_V4_ADDR} on ${HOST_TMFIFO_IF}"
  if ! ip -4 addr show dev "${HOST_TMFIFO_IF}" | grep -q "${BF_V4_IP}"; then
    sudo ip addr add "${BF_V4_ADDR}" dev "${HOST_TMFIFO_IF}" 2>/dev/null || true
  fi

  echo "[BF] Set IPv4 default route via ${HOST_V4_IP}"
  sudo ip route del default 2>/dev/null || true
  sudo ip route add default via ${HOST_V4_IP} dev "${HOST_TMFIFO_IF}" metric 10 2>/dev/null || true
fi

if [[ "${MODE}" == "ipv6" || "${MODE}" == "dual" ]]; then
  echo "[BF] Detect interfaces that provide RA default routes (if any)"
  RA_IFS=\$(ip -6 route show default proto ra 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(\$i=="dev") print \$(i+1)}' | sort -u | tr '\n' ' ')
  echo "[BF] RA default-route interfaces detected: \${RA_IFS:-<none>}"

  echo "[BF] Ensure IPv6 ${BF_V6_ADDR} on ${HOST_TMFIFO_IF}"
  if ! ip -6 addr show dev "${HOST_TMFIFO_IF}" | grep -q "${BF_V6_IP}"; then
    sudo ip -6 addr add "${BF_V6_ADDR}" dev "${HOST_TMFIFO_IF}"
  fi

  echo "[BF] Remove RA-learned IPv6 default route(s)"
  sudo ip -6 route del default proto ra 2>/dev/null || true

  echo "[BF] Set IPv6 default route via ${HOST_V6_IP}"
  sudo ip -6 route del default 2>/dev/null || true
  sudo ip -6 route add default via ${HOST_V6_IP} dev "${HOST_TMFIFO_IF}" metric 10

  echo "[BF] Disable accept_ra globally"
  sudo sysctl -w net.ipv6.conf.all.accept_ra=0 >/dev/null || true

  echo "[BF] Disable accept_ra on RA default-route interfaces"
  for IF in \${RA_IFS}; do
    if ip link show "\${IF}" >/dev/null 2>&1; then
      sudo sysctl -w "net.ipv6.conf.\${IF}.accept_ra=0" >/dev/null || true
      echo "[BF] accept_ra=0 on \${IF}"
    fi
  done
fi

echo "[BF] Set DNS to host (dnsmasq->127.0.0.53)"
sudo bash -c 'cat > /etc/resolv.conf <<EOR
${BF_RESOLV_CONTENT}
EOR'

echo "[BF] Routes now:"
ip route || true
ip -6 route || true

echo "[BF] DNS sanity check:"
getent ahosts linux.mellanox.com | head -n 5 || true
EOF

# ---- Validation ----
log "Validation: BF tmfifo addresses"
"${BF_SSH_CMD[@]}" "${BF_SSH_USER}@${BF_SSH_HOST}" "ip addr show ${HOST_TMFIFO_IF} | sed -n '1,220p'"

if [[ "${MODE}" == "ipv6" || "${MODE}" == "dual" ]]; then
  log "Validation: BF IPv6 connectivity + DNS"
  "${BF_SSH_CMD[@]}" "${BF_SSH_USER}@${BF_SSH_HOST}" "ip -6 route get 2606:4700:4700::1111 || true"
  "${BF_SSH_CMD[@]}" "${BF_SSH_USER}@${BF_SSH_HOST}" "ping6 -c 2 2606:4700:4700::1111 || true"
  "${BF_SSH_CMD[@]}" "${BF_SSH_USER}@${BF_SSH_HOST}" "curl -6 -sS https://ifconfig.co || true; echo"
fi

if [[ "${MODE}" == "ipv4" || "${MODE}" == "dual" ]]; then
  log "Validation: BF IPv4 connectivity + DNS (requires host IPv4 egress)"
  "${BF_SSH_CMD[@]}" "${BF_SSH_USER}@${BF_SSH_HOST}" "ip route get 1.1.1.1 || true"
  "${BF_SSH_CMD[@]}" "${BF_SSH_USER}@${BF_SSH_HOST}" "ping -c 2 1.1.1.1 || true"
  "${BF_SSH_CMD[@]}" "${BF_SSH_USER}@${BF_SSH_HOST}" "curl -4 -sS https://ifconfig.co || true; echo"
fi

log "Host: dnsmasq status"
systemctl --no-pager --full status dnsmasq | sed -n '1,50p' || true

if [[ "${MODE}" == "ipv6" || "${MODE}" == "dual" ]]; then
  log "Host: ip6tables NAT counters"
  ip6tables -t nat -L -v -n | sed -n '1,160p'
fi
if [[ "${MODE}" == "ipv4" || "${MODE}" == "dual" ]]; then
  log "Host: iptables NAT counters"
  iptables -t nat -L -v -n | sed -n '1,160p'
fi

log "Done."