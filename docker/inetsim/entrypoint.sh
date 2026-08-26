#!/bin/sh
set -e

# dns_default_ip has to be the host's own libvirt-bridge-facing IP, which
# varies per machine and can't be baked in at build time. Fail fast and
# loud rather than silently answering DNS queries with the wrong IP.
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

# Narrowed from 0.0.0.0 to just this interface: the guest VM only ever
# reaches inetsim via the libvirt bridge, and 0.0.0.0 meant nothing else
# on the host could bind port 443 (collided with malwhere-misp's own).
sed -i "s/^service_bind_address .*/service_bind_address ${LIBVIRT_GATEWAY}/;s/^#service_bind_address .*/service_bind_address ${LIBVIRT_GATEWAY}/" \
    /etc/inetsim/inetsim.conf
grep -q "^service_bind_address ${LIBVIRT_GATEWAY}$" /etc/inetsim/inetsim.conf || {
    echo "FATAL: failed to patch service_bind_address into inetsim.conf." >&2
    exit 1
}

# /var/log/inetsim is bind-mounted from the host (see docker-compose.yml),
# which overrides whatever ownership the package's postinst set up at build
# time. Per-connection handlers run as the unprivileged `inetsim` user
# (service_run_as_user), so they need write access here or logging silently
# breaks.
#
# INetSim::Log itself refuses to start unless its main/sub/debug logfiles
# have group r/w bits set (perl5/INetSim/Log.pm checks `(mode & 0060) ==
# 0060` and exits with "No group r/w permissions on main logfile" otherwise
# -- this is a hard requirement in INetSim's own code, not something
# inetsim.conf can relax). Docker's default umask (022) makes any logfile
# INetSim creates fresh come out 644 (no group write), so it dies on every
# single start with that exact error. `umask 002` makes new files 664
# instead. Also sweep any files left over from a prior run (started before
# this fix existed, or created under the wrong umask) since chmod on the
# directory alone doesn't touch files already inside it.
mkdir -p /var/log/inetsim
chown -R inetsim:inetsim /var/log/inetsim
find /var/log/inetsim -type d -exec chmod 0770 {} +
find /var/log/inetsim -type f -exec chmod 0660 {} +
umask 002

# INetSim's own DNS service is disabled at build time (Dockerfile comments
# out `start_service dns` -- it's non-functional on this base image, see
# that comment for why). This dnsmasq instance does the exact same job
# dns_default_ip was supposed to: answer every single query, for every
# domain, with our own fake IP, so the guest VM never gets a real DNS
# answer. Runs as its own background daemon (dnsmasq's normal behavior,
# not `exec`'d) so inetsim itself stays PID 1; `set -e` above means a bind
# failure here (e.g. something else still holding port 53 on this address)
# aborts the container instead of silently leaving DNS unanswered.
cat > /etc/dnsmasq-blackhole.conf <<EOF
port=53
bind-interfaces
listen-address=${LIBVIRT_GATEWAY}
no-resolv
no-hosts
address=/#/${LIBVIRT_GATEWAY}
user=nobody
group=nogroup
EOF
dnsmasq --conf-file=/etc/dnsmasq-blackhole.conf

exec "$@"
