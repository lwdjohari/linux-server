#!/usr/bin/env bash
# portctl.sh - Firewall + SELinux port control for Oracle Linux 9 / RHEL 9
# Author: Megah Djohari
# Features:
#   - open/close ports (firewalld)
#   - optional SELinux port mapping (--type ssh_port_t|http_port_t|...)
#   - limit by source CIDR (--source 203.0.113.0/24) using rich rules
#   - bulk ports support (space-separated list)
#   - dry-run mode (prints actions only)
#   - logging (/var/log/portctl.log)
#
# Usage examples:
#   ./portctl.sh open 4422/tcp --type ssh_port_t
#   ./portctl.sh open 8080/tcp 8081/tcp --type http_port_t
#   ./portctl.sh open 9090/tcp --source 203.0.113.0/24
#   ./portctl.sh close 9090/tcp --source 203.0.113.0/24
#   ./portctl.sh list
#   ./portctl.sh open 9100/tcp --dry-run --type http_port_t --source 10.0.0.0/8

set -euo pipefail

LOGFILE="/var/log/portctl.log"
ACTION="${1:-}"
shift || true

DRY_RUN="no"
ZONE=""
SE_TYPE=""
SOURCE=""
KEEP_SE="no"
PORTS=()

usage() {
  cat <<'EOF'
Usage:
  portctl.sh open  <port/proto> [more ports...] [--type SELINUX_TYPE] [--zone ZONE] [--source CIDR] [--dry-run]
  portctl.sh close <port/proto> [more ports...] [--type SELINUX_TYPE] [--zone ZONE] [--source CIDR] [--keep-selinux] [--dry-run]
  portctl.sh list [--zone ZONE]

Examples:
  portctl.sh open 4422/tcp --type ssh_port_t
  portctl.sh open 8080/tcp 8081/tcp --type http_port_t
  portctl.sh open 9090/tcp --source 203.0.113.0/24
  portctl.sh close 9090/tcp --source 203.0.113.0/24
  portctl.sh close 22/tcp
  portctl.sh list
EOF
  exit 1
}

log()  { echo "$(date '+%F %T') $*" | tee -a "$LOGFILE" >&2; }
say()  { echo "$*"; }
run()  { if [[ "$DRY_RUN" == "yes" ]]; then echo "[DRY] $*"; else eval "$@"; fi; }
req()  { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing $1"; exit 1; }; }

# --- parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN="yes"; shift;;
    --zone)    ZONE="${2:-}"; shift 2;;
    --type)    SE_TYPE="${2:-}"; shift 2;;
    --source)  SOURCE="${2:-}"; shift 2;;
    --keep-selinux) KEEP_SE="yes"; shift;;
    -*|--*) echo "Unknown option: $1"; usage;;
    *) PORTS+=("$1"); shift;;
  esac
done

# --- deps ---
if [[ "$ACTION" != "list" && "${#PORTS[@]}" -eq 0 ]]; then usage; fi
req firewall-cmd
systemctl is-active firewalld >/dev/null 2>&1 || run "systemctl enable --now firewalld"
if ! command -v semanage >/dev/null 2>&1; then run "dnf -y install policycoreutils-python-utils >/dev/null"
fi

zone_opt() { [[ -n "$ZONE" ]] && echo "--zone $ZONE" || true; }

# Validate port/proto
split_port_proto() {
  local spec="$1"
  if [[ ! "$spec" =~ ^([0-9]{1,5})/(tcp|udp)$ ]]; then
    echo "Invalid port spec: $spec (use NNNN/tcp or NNNN/udp)"; exit 1
  fi
  PORT="${BASH_REMATCH[1]}"; PROTO="${BASH_REMATCH[2]}"
  if (( PORT < 1 || PORT > 65535 )); then echo "Invalid port: $PORT"; exit 1; fi
}

# SELinux helpers
se_port_exists() {
  local type="$1" proto="$2" port="$3"
  semanage port -l | awk -v t="$type" -v p="$proto" -v n="$port" '
    $1==t && $3==p { for(i=4;i<=NF;i++){ split($i,a,","); for(j in a){ if(a[j]==n){f=1} } } }
    END{ exit(f?0:1) }'
}
se_add_or_mod() {
  local type="$1" proto="$2" port="$3"
  if semanage port -l | awk '$1=="'"$type"'"{f=1}END{exit(f?0:1)}'; then
    if ! se_port_exists "$type" "$proto" "$port"; then
      run "semanage port -m -t $type -p $proto $port"
    fi
  else
    run "semanage port -a -t $type -p $proto $port"
  fi
}
se_remove_if_present() {
  local type="$1" proto="$2" port="$3"
  se_port_exists "$type" "$proto" "$port" && run "semanage port -d -t $type -p $proto $port" || true
}

# Firewalld helpers (basic and rich rules)
fw_reload() { run "firewall-cmd --reload >/dev/null"; }
fw_list_ports() {
  if [[ -n "$ZONE" ]]; then
    say "Zone: $ZONE"
    firewall-cmd --zone "$ZONE" --list-ports
    say "Rich rules:"; firewall-cmd --zone "$ZONE" --list-rich-rules
  else
    say "Default zone: $(firewall-cmd --get-default-zone)"
    firewall-cmd --list-ports
    say "Rich rules:"; firewall-cmd --list-rich-rules
  fi
}
fw_add_port() {
  local spec="$1"
  run "firewall-cmd --permanent $(zone_opt) --add-port=$spec >/dev/null"
}
fw_remove_port() {
  local spec="$1"
  run "firewall-cmd --permanent $(zone_opt) --remove-port=$spec >/dev/null || true"
}
# Rich rule generator: accept from SOURCE to PORT/PROTO
rich_rule_for() {
  local source_cidr="$1" port="$2" proto="$3"
  # IPv4/IPv6 family auto-detect from CIDR
  if [[ "$source_cidr" == *:* ]]; then
    echo "rule family=\"ipv6\" source address=\"$source_cidr\" port port=\"$port\" protocol=\"$proto\" accept"
  else
    echo "rule family=\"ipv4\" source address=\"$source_cidr\" port port=\"$port\" protocol=\"$proto\" accept"
  fi
}
fw_add_rich() {
  local rule="$1"
  run "firewall-cmd --permanent $(zone_opt) --add-rich-rule='$rule' >/dev/null"
}
fw_remove_rich() {
  local rule="$1"
  run "firewall-cmd --permanent $(zone_opt) --remove-rich-rule='$rule' >/dev/null || true"
}

# --- actions ---
case "$ACTION" in
  list)
    fw_list_ports
    echo
    echo "SELinux (common types):"
    for t in ssh_port_t http_port_t https_port_t mysqld_port_t postgresql_port_t redis_port_t; do
      semanage port -l | awk -v T="$t" '$1==T{print}'
    done
    ;;

  open)
    for spec in "${PORTS[@]}"; do
      split_port_proto "$spec"
      if [[ -n "$SOURCE" ]]; then
        # Source-limited opening via rich rule
        RULE="$(rich_rule_for "$SOURCE" "$PORT" "$PROTO")"
        log "OPEN (rich) $spec from $SOURCE $( [[ -n "$ZONE" ]] && echo "zone=$ZONE" )"
        fw_add_rich "$RULE"
      else
        log "OPEN $spec $( [[ -n "$ZONE" ]] && echo "zone=$ZONE" )"
        fw_add_port "$spec"
      fi
      fw_reload

      # SELinux mapping if requested
      if [[ -n "$SE_TYPE" ]]; then
        log "SELinux map $PORT/$PROTO -> $SE_TYPE"
        se_add_or_mod "$SE_TYPE" "$PROTO" "$PORT"
      else
        log "SELinux: no --type provided (skipped)"
      fi
    done
    ;;

  close)
    for spec in "${PORTS[@]}"; do
      split_port_proto "$spec"
      if [[ -n "$SOURCE" ]]; then
        RULE="$(rich_rule_for "$SOURCE" "$PORT" "$PROTO")"
        log "CLOSE (rich) $spec from $SOURCE $( [[ -n "$ZONE" ]] && echo "zone=$ZONE" )"
        fw_remove_rich "$RULE"
      else
        log "CLOSE $spec $( [[ -n "$ZONE" ]] && echo "zone=$ZONE" )"
        fw_remove_port "$spec"
      fi
      fw_reload

      # Optionally remove SELinux mapping
      if [[ "$KEEP_SE" == "no" && -n "$SE_TYPE" ]]; then
        log "SELinux unmap $PORT/$PROTO from $SE_TYPE"
        se_remove_if_present "$SE_TYPE" "$PROTO" "$PORT"
      elif [[ -n "$SE_TYPE" ]]; then
        log "SELinux mapping kept for $SE_TYPE (use without --keep-selinux to remove)"
      fi
    done
    ;;

  *) usage;;
esac
