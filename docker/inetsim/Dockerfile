# =============================================================================
# malwhere — inetsim
# Simulated internet for CAPE's guest VM. See dynamic pipeline design v1
# §5: default containment mode for guest detonations — every outbound
# attempt gets a fake answer and is logged, nothing reaches the real
# internet. Runs with network_mode: host (see docker-compose.yml and
# routing.conf's [inetsim] comments for why — this has to be reachable
# from the guest VM via the host's libvirt bridge, which a Docker bridge
# network can't provide). Package comes straight from Ubuntu's universe
# repo, so we patch only what's necessary and otherwise keep upstream's
# defaults (broad protocol coverage: dns, http, https, smtp(s), pop3(s),
# ftp(s), irc, ntp, and the low-level echo/discard/chargen/dummy catch-alls).
# =============================================================================

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends inetsim openssl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# --- Config patch (build-time, host-agnostic only) -------------------------
# service_bind_address: listen on all interfaces. cape and inetsim both run
#   with network_mode: host (see docker-compose.yml + routing.conf comments
#   for why), so "all interfaces" here means the host's real interfaces —
#   that's exactly what's needed for the guest VM to reach this service.
# service_run_as_user: bind the privileged ports (53/80/443) as root, then
#   drop to the unprivileged inetsim user for each connection handler —
#   the package creates this user in postinst, no extra setup needed.
#
# dns_default_ip is NOT patched here — it has to be the host's own
# libvirt-bridge-facing IP, which varies per machine and isn't known at
# build time. entrypoint.sh patches it at container start from the
# LIBVIRT_GATEWAY environment variable (sourced from .env, written by
# scripts/host-prereqs.sh — same value CAPE's own conf files reference as
# %(ENV:LIBVIRT_GATEWAY)s).
RUN sed -i \
        -e 's/^#service_bind_address .*/service_bind_address 0.0.0.0/' \
        -e 's/^#service_run_as_user .*/service_run_as_user inetsim/' \
        /etc/inetsim/inetsim.conf && \
    grep -q '^service_bind_address 0.0.0.0' /etc/inetsim/inetsim.conf && \
    grep -q '^service_run_as_user inetsim' /etc/inetsim/inetsim.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD nc -z 127.0.0.1 80 || exit 1

# Runs in the foreground by design (the init.d script backgrounds this same
# binary with start-stop-daemon for a real host install — we skip that and
# let it be PID 1 directly, which is what Docker wants).
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/bin/inetsim"]
