#!/usr/bin/env bash
# =============================================================================
# malwhere — scripts/host-prereqs.sh
#
# Everything docker-compose.yml CANNOT set up, because cape and inetsim run
# with network_mode: host and depend on libvirt/KVM being present on the
# HOST itself, not inside a container (see docker-compose.yml's top-level
# networks: comment, and dynamic pipeline design v1 for why).
#
# What this script does:
#   1. Installs qemu-kvm + libvirt on the host (idempotent — safe to re-run).
#   2. Verifies /dev/kvm is actually usable (not just present).
#   3. Ensures libvirt's default network exists and is running.
#   4. Discovers the real bridge interface / subnet / gateway IP libvirt is
#      actually using — this is NOT guessable in advance and varies by
#      machine, which is exactly why routing.conf, kvm.conf, and
#      cuckoo.conf all have PLACEHOLDER comments instead of real values.
#   5. Writes LIBVIRT_GATEWAY and LIBVIRT_BRIDGE to .env so inetsim's
#      entrypoint and CAPE's own %(ENV:...)s config interpolation can pick
#      them up, instead of needing an image rebuild every time this value
#      changes.
#   6. Prints the exact lines to paste into cape-conf/{routing,kvm,cuckoo}.conf
#      if the discovered bridge differs from the virbr0/192.168.122.0/24
#      default this repo assumes.
#
# Run with sudo. Safe to re-run — every step checks before acting.
# =============================================================================
set -euo pipefail

# Force English output from virsh/libvirt regardless of system locale — the
# script parses virsh's human-readable output (e.g. grepping for "Active:"),
# and that text is localized based on $LANG/$LC_ALL. Without this, a
# non-English locale silently breaks the parsing below rather than erroring
# clearly, which is exactly what happened the first time this ran (grep
# missed a localized "active" label, fell through to an unconditional
# net-start, which then failed because the network was already active).
export LC_ALL=C
export LANG=C

log()  { printf '\033[1;34m[host-prereqs]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[host-prereqs][warn]\033[0m %s\n' "$1" >&2; }
fail() { printf '\033[1;31m[host-prereqs][fail]\033[0m %s\n' "$1" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    fail "Run with sudo — installing packages and touching libvirt/systemd needs root."
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"

# --- 1. Packages -------------------------------------------------------------
log "Checking KVM/libvirt packages..."
# libvirt-daemon-config-network ships /usr/share/libvirt/networks/default.xml
# — the actual default NAT network template. It's a Recommends of
# libvirt-daemon-system, not a hard Depends, so --no-install-recommends
# below was silently skipping it. That's the real root cause behind the
# "default network doesn't exist" warning further down: nothing on this
# machine had ever created it in the first place.
NEEDED_PKGS="qemu-kvm libvirt-daemon-system libvirt-daemon-config-network libvirt-clients bridge-utils virtinst uidmap libvirt-dev libguestfs-tools"
MISSING_PKGS=""
for pkg in $NEEDED_PKGS; do
    dpkg -s "$pkg" >/dev/null 2>&1 || MISSING_PKGS="${MISSING_PKGS} ${pkg}"
done
if [ -n "$MISSING_PKGS" ]; then
    log "Installing:${MISSING_PKGS}"
    apt-get update
    # shellcheck disable=SC2086
    apt-get install -y --no-install-recommends ${MISSING_PKGS}
else
    log "All required packages already installed."
fi

# --- 2. KVM device usability ---------------------------------------------------
log "Checking /dev/kvm..."
[ -e /dev/kvm ] || fail "/dev/kvm doesn't exist — is virtualization (VT-x/AMD-V) enabled in BIOS/UEFI, and the kvm/kvm_intel or kvm_amd kernel module loaded?"
if command -v kvm-ok >/dev/null 2>&1; then
    kvm-ok || fail "kvm-ok reports KVM acceleration is not available — see its output above."
else
    warn "kvm-ok not found (usually from cpu-checker package) — skipping that specific check, /dev/kvm exists so proceeding."
fi

# --- 3. libvirtd running -------------------------------------------------------
log "Ensuring libvirtd is enabled and running..."
systemctl enable --now libvirtd

# systemctl is-active can report "active" even when libvirtd hasn't actually
# finished coming up (e.g. it depends on virtlogd.socket via a hard
# Requires=, and Type=notify readiness can lag). Test the real thing —
# an actual virsh connection — instead of trusting that flag.
#
# libvirtd runs with --timeout 120 (socket-activated, shuts itself down
# after 120s idle, springs back up on the next connection) — that's
# expected, normal behavior, not a crash. What's NOT guaranteed to be
# instant is a fresh spawn: it's been observed intermittently logging
# "End of file while reading data: Input/output error" right after
# starting, then recovering within a few seconds on its own. 10s of
# retries wasn't enough headroom for that; give it real room instead of
# guessing again.
log "Verifying libvirtd actually accepts connections (not just systemctl's view of it)..."
LIBVIRT_UP=0
for i in $(seq 1 30); do
    if virsh -c qemu:///system list >/dev/null 2>&1; then
        LIBVIRT_UP=1
        break
    fi
    sleep 2
done
if [ "$LIBVIRT_UP" -ne 1 ]; then
    fail "libvirtd is enabled but not actually accepting connections after 60s. Run these manually and check the output:
  systemctl status libvirtd libvirtd.socket virtlogd.socket
  journalctl -u libvirtd -e --no-pager
  virsh -c qemu:///system list
If journalctl shows 'End of file while reading data: Input/output error' repeating rather than clearing up after a few seconds, check for a broken storage pool libvirtd is trying to probe on startup: virsh pool-list --all — an unreachable/misconfigured pool is a common cause of that specific message."
fi

# Give the invoking (non-root) user libvirt/kvm group access, if this was
# run via sudo from a real user session.
if [ -n "${SUDO_USER:-}" ]; then
    log "Adding ${SUDO_USER} to libvirt and kvm groups (log out/in for it to take effect)..."
    usermod -aG libvirt,kvm "$SUDO_USER" || warn "Could not add ${SUDO_USER} to libvirt/kvm groups — add manually if needed."
fi

# --- 4. Default libvirt network ------------------------------------------------
log "Ensuring libvirt's default network exists and is active..."
if ! virsh net-info default >/dev/null 2>&1; then
    log "libvirt 'default' network doesn't exist — defining it from the package template."
    TEMPLATE="/usr/share/libvirt/networks/default.xml"
    [ -f "$TEMPLATE" ] || fail "Expected ${TEMPLATE} from libvirt-daemon-config-network but it's not there — package install may have failed silently, check: dpkg -L libvirt-daemon-config-network"
    virsh net-define "$TEMPLATE" || fail "virsh net-define ${TEMPLATE} failed — run it manually to see the actual error."
fi
# Use `net-list --name` (active networks, bare names, one per line) instead
# of parsing net-info's human-readable table — net-info's field formatting
# turned out to be too fragile to grep reliably (this failed twice against
# real output despite LC_ALL=C). --name is virsh's own scripting-oriented
# interface for exactly this kind of check: nothing to misparse.
is_default_active() { virsh net-list --name 2>/dev/null | grep -qx "default"; }

virsh net-autostart default >/dev/null 2>&1 || true
if ! is_default_active; then
    virsh net-start default 2>&1 || true
    is_default_active || \
        fail "libvirt's default network isn't active and won't start. Run these manually and check the output: virsh net-info default   /   virsh net-list --all"
fi

# --- 5. Discover the real bridge/subnet/gateway --------------------------------
log "Discovering the actual bridge interface and gateway IP..."
NET_NAME="default"
# All three pulled from net-dumpxml's XML output, not net-info's
# human-readable table — XML is structured data with fixed attribute
# names, not subject to the same free-text parsing fragility that broke
# the net-info-based check above.
#
# `|| true` on each: without it, a failing `virsh net-dumpxml` here (e.g.
# network still somehow missing) makes bash's pipefail promote that
# failure through the pipe even when the trailing `head -1` succeeds
# trivially on empty input — and set -e then exits the whole script
# SILENTLY right here, before ever reaching the explicit fail() check
# below. That's exactly what happened the first time this ran against a
# genuinely-missing network: no error message, script just stopped. `||
# true` guarantees we always reach the informative fail() instead.
BRIDGE_IF="$(virsh net-dumpxml "$NET_NAME" 2>/dev/null | grep -oP "(?<=<bridge name=')[^']+" | head -1 || true)"
GATEWAY_IP="$(virsh net-dumpxml "$NET_NAME" 2>/dev/null | grep -oP "(?<=<ip address=')[0-9.]+" | head -1 || true)"
SUBNET_MASK="$(virsh net-dumpxml "$NET_NAME" 2>/dev/null | grep -oP "(?<=netmask=')[0-9.]+" | head -1 || true)"

if [ -z "$BRIDGE_IF" ] || [ -z "$GATEWAY_IP" ]; then
    fail "Could not discover libvirt's bridge/gateway via 'virsh net-dumpxml ${NET_NAME}'. Run that command manually and fill in routing.conf/kvm.conf/cuckoo.conf's PLACEHOLDER values by hand."
fi

log "Discovered: bridge=${BRIDGE_IF}  gateway=${GATEWAY_IP}  netmask=${SUBNET_MASK:-unknown}"

if [ "$BRIDGE_IF" != "virbr0" ] || [ "$GATEWAY_IP" != "192.168.122.1" ]; then
    log "This differs from libvirt's usual virbr0/192.168.122.0-24 default — no problem, cape-conf/*.conf reference these via %(ENV:LIBVIRT_GATEWAY)s / %(ENV:LIBVIRT_BRIDGE)s, so writing the discovered values to .env below is all that's needed. Nothing to hand-edit."
fi

# --- 6. Write .env -------------------------------------------------------------
log "Writing LIBVIRT_GATEWAY and LIBVIRT_BRIDGE to ${ENV_FILE}..."
touch "$ENV_FILE"
for kv in "LIBVIRT_GATEWAY=${GATEWAY_IP}" "LIBVIRT_BRIDGE=${BRIDGE_IF}"; do
    key="${kv%%=*}"
    if grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${kv}|" "$ENV_FILE"
    else
        echo "$kv" >> "$ENV_FILE"
    fi
done
if ! grep -q "^GUEST_VM_IP=" "$ENV_FILE"; then
    echo "GUEST_VM_IP=" >> "$ENV_FILE"
    warn "GUEST_VM_IP left blank in .env — this isn't auto-discoverable, it's whatever static IP you assign the guest VM when you create it. Fill it in by hand before bringing up the sandbox profile."
fi

log "Done. Guest VMs on ${BRIDGE_IF} will now be answered by inetsim at ${GATEWAY_IP} once the sandbox profile is up."
log "Next: create the win10x64 guest VM, set GUEST_VM_IP in .env, then:"
log "  docker compose --profile core --profile sandbox build inetsim cape"
