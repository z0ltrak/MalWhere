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
# silently skip it -- listed explicitly here for that reason. virt-viewer
# isn't pulled in by any of the above and isn't present on every Ubuntu
# build by default (needed later for "Creating the Guest VM"'s Step 4).
NEEDED_PKGS="qemu-kvm libvirt-daemon-system libvirt-daemon-config-network libvirt-clients bridge-utils virtinst uidmap libvirt-dev libguestfs-tools virt-viewer"
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

log "Checking libvirt's default network for its own DNS forwarder..."
# libvirt's own dnsmasq for the default network binds the exact same
# bridge gateway IP (port 53) that inetsim's dns_default_ip answers from.
# Whichever process wins that bind race gets ALL of the guest VM's DNS
# traffic -- and libvirt's dnsmasq reliably wins it, silently handing the
# guest real internet DNS answers instead of inetsim's fake one. Found by
# tracing a real ATT&CK-technique-count discrepancy between runs: with
# inetsim fully healthy, the guest still resolved genuine Microsoft/Azure
# infrastructure during a detonation. `<dns enable='no'/>` turns libvirt's
# forwarder off so only inetsim (its dnsmasq blackhole, see
# docker/inetsim/entrypoint.sh) answers on that address.
if virsh net-dumpxml default 2>/dev/null | grep -q "<dns enable='no'/>"; then
    log "libvirt's DNS forwarder is already disabled on the default network."
elif virsh list --name 2>/dev/null | grep -q .; then
    warn "A guest VM is currently running -- skipping the DNS-forwarder fix to avoid dropping its network mid-analysis. Shut the VM down and re-run this script to apply it."
else
    TMP_NET_XML="$(mktemp)"
    virsh net-dumpxml default > "$TMP_NET_XML"
    sed -i "/<bridge /a\\  <dns enable='no'/>" "$TMP_NET_XML"
    virsh net-define "$TMP_NET_XML" || fail "Failed to define the patched default network XML. Run manually: virsh net-edit default and add <dns enable='no'/> inside the <network> element."
    virsh net-destroy default >/dev/null 2>&1 || true
    virsh net-start default || fail "Failed to restart libvirt's default network after disabling DNS. Run manually: virsh net-start default"
    rm -f "$TMP_NET_XML"
    log "libvirt's DNS forwarder disabled; default network restarted."
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

log "Ensuring a host user exists at the cape container's UID..."
# Confirmed hitting this for real: libvirtd's OWN log (journalctl -u
# libvirtd) showed "Failed to find user record for uid 'N'" immediately
# followed by dropping the connection, on every single attempt from the
# cape container -- even with auth_unix_rw="none" (see the section above)
# active the whole time. That setting only controls the AUTH scheme; this
# is libvirtd unconditionally resolving the connecting peer's UID to a
# username for its own identity/audit logging, regardless of auth mode --
# nothing in auth_unix_rw gates that call. If the host has no user at that
# UID, the lookup fails and libvirtd tears down the connection outright.
# The container's "cape" UID isn't pinned in the base image (can differ
# build to build -- see docker/cape/Dockerfile's fix 8), so this discovers
# whatever UID THIS machine's build actually assigned rather than
# hardcoding a number, and only acts if cape:kvm has actually been built
# (it's fine to run this script before that -- see README's documented
# order -- just re-run it after building cape:kvm to pick this up).
if docker image inspect cape:kvm >/dev/null 2>&1; then
    # --entrypoint override is required: this image's default entrypoint is
    # systemd, not a shell, so a plain `docker run cape:kvm id -u cape`
    # silently exits 255 with no output at all -- confirmed the hard way.
    CAPE_UID="$(docker run --rm --entrypoint /usr/bin/id cape:kvm -u cape 2>/dev/null || true)"
    if [ -z "$CAPE_UID" ]; then
        warn "Could not determine the cape user's UID from the cape:kvm image — skipping host user alignment. Check manually: docker run --rm cape:kvm id -u cape"
    elif getent passwd "$CAPE_UID" >/dev/null 2>&1; then
        log "UID ${CAPE_UID} (cape container's UID) already resolves to a host user ($(getent passwd "$CAPE_UID" | cut -d: -f1)) — nothing to do."
    else
        log "No host user at UID ${CAPE_UID} — creating a placeholder system account so libvirtd's identity lookup succeeds."
        useradd --system --no-create-home --no-user-group -u "$CAPE_UID" -g nogroup -s /usr/sbin/nologin \
            -c "malwhere placeholder for the cape container's UID, libvirtd identity lookup only, not a real login account" \
            cape-container-uid \
            || warn "Failed to create the placeholder user — create one manually: useradd --system --no-create-home -u ${CAPE_UID} -g nogroup -s /usr/sbin/nologin cape-container-uid"
    fi
else
    warn "cape:kvm image not built yet — once it is (see README 'Building the CAPE Image'), re-run this script to also align a host user with the cape container's UID (needed for libvirtd's connection-identity lookup)."
fi

# docker/resubmit_queue is a bind mount (static's `./resubmit_queue:/resubmit:ro`,
# docker-compose.yml) and entirely gitignored, so nothing pre-creates it. If
# `docker compose up` (Quickstart) is the first thing to ever touch that
# path -- which the documented setup order makes likely, since Quickstart
# runs before run_pipeline.py ever has -- Docker auto-creates the missing
# bind-mount source itself, as root. run_pipeline.py also pre-creates this
# host-side before starting `static`, but that only helps if this directory
# doesn't already exist; it can't fix one Docker already created as root,
# since the invoking (non-root) user has no write permission on a root-owned
# parent to begin with. Doing it here, as root, before any `docker compose
# up` has necessarily run yet, closes that ordering hole -- and re-running
# this (idempotent, safe any time) reclaims ownership even if it's already
# happened.
if [ -n "${SUDO_USER:-}" ]; then
    log "Ensuring docker/resubmit_queue is owned by ${SUDO_USER}, not root..."
    mkdir -p "${REPO_ROOT}/resubmit_queue/manifest" "${REPO_ROOT}/resubmit_queue/artifacts"
    chown -R "${SUDO_USER}:$(id -gn "$SUDO_USER")" "${REPO_ROOT}/resubmit_queue"
fi

# ../dynamic/reports/inetsim is another bind mount (inetsim's
# `../dynamic/reports/inetsim:/var/log/inetsim`, docker-compose.yml) with
# the same ordering hole: inetsim's own service runs as a non-root user
# inside the container, so if Docker auto-creates this bind-mount source
# before anything else touches it, the host directory ends up owned by
# whatever UID that is -- observed as UID 100/GID 101, which happen to
# collide with unrelated host system accounts (dhcpcd/messagebus) purely by
# number, locking the invoking user out of even reading it (breaks plain
# `git status` with a "Permission denied" warning).
if [ -n "${SUDO_USER:-}" ]; then
    log "Ensuring dynamic/reports/inetsim is owned by ${SUDO_USER}, not inetsim's container UID..."
    mkdir -p "$(dirname "${REPO_ROOT}")/dynamic/reports/inetsim"
    chown -R "${SUDO_USER}:$(id -gn "$SUDO_USER")" "$(dirname "${REPO_ROOT}")/dynamic/reports/inetsim"
fi

log "Done. Guest VMs on ${BRIDGE_IF} will now be answered by inetsim at ${GATEWAY_IP} once the sandbox profile is up."
log "Next: create the win10x64 guest VM, set GUEST_VM_IP in .env, then:"
log "  docker compose --profile core --profile sandbox build inetsim cape"
