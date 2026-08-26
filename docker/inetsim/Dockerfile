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
# defaults (broad protocol coverage: http, https, smtp(s), pop3(s),
# ftp(s), irc, ntp, and the low-level echo/discard/chargen/dummy catch-alls
# -- DNS is a separate dnsmasq blackhole, INetSim's own DNS service is
# disabled below, see entrypoint.sh for why).
# =============================================================================

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends inetsim openssl netcat-openbsd dnsmasq && \
    rm -rf /var/lib/apt/lists/*

# --- Config patch (build-time, host-agnostic only) -------------------------
# service_run_as_user: bind the privileged ports (53/80/443) as root, then
#   drop to the unprivileged inetsim user for each connection handler —
#   the package creates this user in postinst, no extra setup needed.
#
# service_bind_address is NOT patched here (was hardcoded to 0.0.0.0 --
# "all interfaces" -- until this collided with malwhere-misp's own need for
# host port 443: both are host-network-mode/host-port-mapped services that
# want it, and the guest VM only ever reaches inetsim through one specific
# interface anyway, the libvirt bridge). Patched at runtime in entrypoint.sh
# to the same LIBVIRT_GATEWAY IP already used for dns_default_ip below --
# host-agnostic and not known at build time, same reasoning as that one.
RUN sed -i \
        -e 's/^#service_run_as_user .*/service_run_as_user inetsim/' \
        /etc/inetsim/inetsim.conf && \
    grep -q '^service_run_as_user inetsim' /etc/inetsim/inetsim.conf

# INetSim's own DNS service is dead weight on this base image: Ubuntu
# 24.04's libnet-dns-perl (1.44) silently no-ops the deprecated
# Net::DNS::Nameserver->main_loop() API that INetSim 1.3.2 (2020) calls --
# the fork logs "started" and then just exits within seconds, every single
# time, no error. Disabled here and replaced in entrypoint.sh with a tiny
# dedicated dnsmasq instance doing the exact same job dns_default_ip was
# supposed to (answer every query with our own fake IP). Every other
# service (http/https/smtp/...) is unaffected and stays on INetSim as-is.
RUN sed -i 's/^start_service dns$/#start_service dns/' /etc/inetsim/inetsim.conf && \
    grep -q '^#start_service dns$' /etc/inetsim/inetsim.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 127.0.0.1 would silently stop working once service_bind_address narrows
# to LIBVIRT_GATEWAY -- shell form (not exec/JSON form) so this expands the
# container's own env at check time, not build time; the fallback only
# matters if the container somehow starts without LIBVIRT_GATEWAY set
# (entrypoint.sh already fails fast on that before inetsim itself starts).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD nc -z ${LIBVIRT_GATEWAY:-127.0.0.1} 80 || exit 1

# Runs in the foreground by design (the init.d script backgrounds this same
# binary with start-stop-daemon for a real host install — we skip that and
# let it be PID 1 directly, which is what Docker wants).
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/bin/inetsim"]
