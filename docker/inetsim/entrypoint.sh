#!/bin/sh
set -e

# dns_default_ip has to be the host's own libvirt-bridge-facing IP, which
# varies per machine and can't be baked in at build time (see Dockerfile).
# scripts/host-prereqs.sh discovers it and writes it to .env as
# LIBVIRT_GATEWAY; docker-compose.yml passes it through as an environment
# variable. Fail fast and loud rather than silently answering DNS queries
# with the wrong IP — that failure mode is much harder to debug later.
if [ -z "$LIBVIRT_GATEWAY" ]; then
    echo "FATAL: LIBVIRT_GATEWAY is not set." >&2
    echo "Run scripts/host-prereqs.sh to discover it and write .env, then retry." >&2
    exit 1
fi
sed -i "s/^dns_default_ip .*/dns_default_ip ${LIBVIRT_GATEWAY}/;s/^#dns_default_ip .*/dns_default_ip ${LIBVIRT_GATEWAY}/" \
    /etc/inetsim/inetsim.conf
grep -q "^dns_default_ip ${LIBVIRT_GATEWAY}$" /etc/inetsim/inetsim.conf || {
    echo "FATAL: failed to patch dns_default_ip into inetsim.conf." >&2
    exit 1
}

# /var/log/inetsim is bind-mounted from the host (see docker-compose.yml),
# which overrides whatever ownership the package's postinst set up at build
# time. Per-connection handlers run as the unprivileged `inetsim` user
# (service_run_as_user), so they need write access here or logging silently
# breaks.
mkdir -p /var/log/inetsim
chown -R inetsim:inetsim /var/log/inetsim
chmod 0700 /var/log/inetsim

exec "$@"
