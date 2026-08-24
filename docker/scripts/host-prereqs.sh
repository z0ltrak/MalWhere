#!/usr/bin/env bash
# Everything docker-compose.yml can't set up, because cape and inetsim run
# with network_mode: host and depend on libvirt/KVM being present on the
# host itself, not inside a container: installs qemu-kvm/libvirt, verifies
# /dev/kvm is usable, ensures libvirt's default network is running,
# discovers its real bridge/subnet/gateway IP (not guessable in advance,
# hence the PLACEHOLDER values in routing.conf/kvm.conf/cuckoo.conf), and
# writes LIBVIRT_GATEWAY/LIBVIRT_BRIDGE to .env for inetsim's entrypoint
# and CAPE's %(ENV:...)s config interpolation to pick up.
#
# Run with sudo. Safe to re-run — every step checks before acting.
set -euo pipefail

# Force English output: the script parses virsh's human-readable output
# (e.g. grepping for "Active:"), which is localized based on $LANG/$LC_ALL
# and silently breaks the parsing below in a non-English locale.
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

log "Checking KVM/libvirt packages..."
# libvirt-daemon-config-network ships /usr/share/libvirt/networks/default.xml
# (the default NAT network template) as a Recommends, not a hard Depends
# of libvirt-daemon-system, so --no-install-recommends below would
# silently skip it -- listed explicitly here for that reason.
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

log "Checking /dev/kvm..."
[ -e /dev/kvm ] || fail "/dev/kvm doesn't exist — is virtualization (VT-x/AMD-V) enabled in BIOS/UEFI, and the kvm/kvm_intel or kvm_amd kernel module loaded?"
if command -v kvm-ok >/dev/null 2>&1; then
    kvm-ok || fail "kvm-ok reports KVM acceleration is not available — see its output above."
else
    warn "kvm-ok not found (usually from cpu-checker package) — skipping that specific check, /dev/kvm exists so proceeding."
fi

log "Ensuring libvirtd doesn't require polkit for local UNIX-socket connections..."
# Ubuntu's libvirt package is compiled with polkit support, so when
# auth_unix_rw is left unset, libvirtd.conf's own comment says it "will
# default to 'polkit'" -- which authorizes a connecting UNIX-socket peer by
# resolving its UID to a real user record on THIS host. CAPE's containerized
# "cape" user has whatever UID the base image happened to assign it (not
# guaranteed to match ANY real account here -- confirmed hitting this for
# real on a fresh machine: polkit's lookup failed with "Failed to find user
# record for uid '999'", crash-looping cape.service/cape-processor forever,
# since there was no host user at that UID). Access to this socket is
# already gated numerically by group membership (see fix-libvirt-gid.sh's
# own comment: "AF_UNIX permission checks are purely numeric") -- that's
# only actually true when auth_unix_rw="none", which nothing enforced
# before this. Setting it here makes that assumption real instead of
# something that happened to hold by accident on whichever machine still
# has it manually set from early bring-up.
LIBVIRTD_CONF=/etc/libvirt/libvirtd.conf
LIBVIRTD_CONF_CHANGED=0
if ! grep -qE '^\s*auth_unix_rw\s*=\s*"none"' "$LIBVIRTD_CONF"; then
    if grep -qE '^\s*auth_unix_rw\s*=' "$LIBVIRTD_CONF"; then
        sed -i 's/^\s*auth_unix_rw\s*=.*/auth_unix_rw = "none"/' "$LIBVIRTD_CONF"
    else
        printf '\nauth_unix_rw = "none"\n' >> "$LIBVIRTD_CONF"
    fi
    LIBVIRTD_CONF_CHANGED=1
    log "Set auth_unix_rw = \"none\" in ${LIBVIRTD_CONF}."
else
    log "auth_unix_rw already set to \"none\"."
fi

log "Ensuring libvirtd is enabled and running..."
systemctl enable --now libvirtd
if [ "$LIBVIRTD_CONF_CHANGED" -eq 1 ]; then
    # enable --now above is a no-op if libvirtd was already running (won't
    # pick up the config change we just made) -- restart unconditionally so
    # the connection check below tests the ACTUAL post-fix state.
    log "Restarting libvirtd to pick up the auth_unix_rw change..."
    systemctl restart libvirtd
fi

# systemctl is-active can report "active" before libvirtd actually accepts
# connections (Type=notify readiness can lag behind virtlogd.socket).
# libvirtd is socket-activated (--timeout 120, normal to shut down idle
# and respawn on the next connection), but a fresh spawn has been
# observed intermittently logging "End of file while reading data:
# Input/output error" before recovering a few seconds later, so this
# polls the real connection rather than trusting the systemd flag.
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

log "Ensuring libvirt's default network exists and is active..."
if ! virsh net-info default >/dev/null 2>&1; then
    log "libvirt 'default' network doesn't exist — defining it from the package template."
    TEMPLATE="/usr/share/libvirt/networks/default.xml"
    [ -f "$TEMPLATE" ] || fail "Expected ${TEMPLATE} from libvirt-daemon-config-network but it's not there — package install may have failed silently, check: dpkg -L libvirt-daemon-config-network"
    virsh net-define "$TEMPLATE" || fail "virsh net-define ${TEMPLATE} failed — run it manually to see the actual error."
fi
# `net-list --name` (bare names, one per line) rather than net-info's
# human-readable table, whose field formatting is too fragile to grep
# reliably even with LC_ALL=C -- --name is virsh's scripting-oriented
# interface for exactly this kind of check.
is_default_active() { virsh net-list --name 2>/dev/null | grep -qx "default"; }

virsh net-autostart default >/dev/null 2>&1 || true
if ! is_default_active; then
    virsh net-start default 2>&1 || true
    is_default_active || \
        fail "libvirt's default network isn't active and won't start. Run these manually and check the output: virsh net-info default   /   virsh net-list --all"
fi

log "Discovering the actual bridge interface and gateway IP..."
NET_NAME="default"
# Pulled from net-dumpxml's XML output (structured, fixed attribute
# names) rather than net-info's fragile free-text table.
#
# `|| true` on each: without it, a failing `virsh net-dumpxml` makes
# bash's pipefail promote that failure through the pipe even when the
# trailing `head -1` succeeds trivially on empty input, so `set -e`
# would exit the script silently here instead of reaching the
# informative fail() check below.
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
