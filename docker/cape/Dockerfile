# =============================================================================
# malwhere — cape image overlay
#
# Builds FROM cape:kvm (built from our fork, github.com/z0ltrak/kvm-cape-docker,
# kvm branch — see docker-compose.yml's cape service comment) and bakes in
# seven more fixes
# discovered during initial bring-up, so a fresh `docker compose up` doesn't
# require re-discovering any of them by hand:
#
#   1. MongoDB 8.x crashes on startup on Linux kernel >= 6.19 (a TCMalloc/
#      rseq ABI bug — MongoDB SERVER-121912, hit by many unrelated projects,
#      not something specific to this setup). Community-reported workaround
#      via a systemd drop-in; MongoDB's own official fix is downgrading the
#      HOST kernel below 6.19, which isn't something a container image can
#      do. This tunable is expected to be harmless on unaffected kernels —
#      not verified against one here, but low-risk given what it does.
#
#   2. libvirt-python isn't installed in the poetry venv CAPE's own systemd
#      units actually invoke (confirmed via
#      `poetry run python -c "import libvirt"` -> ModuleNotFoundError),
#      so cape-processor.service's KVM/QEMU machinery check fails on every
#      startup. Now fixed at the source: the fork's own Dockerfile
#      (z0ltrak/kvm-cape-docker, commit f1ee3cc) installs libvirt-python
#      into this same venv as part of building cape:kvm. What's left here
#      is just a build-time verification, not a reinstall.
#
#   3. cape.service, cape-web.service, and cape-processor.service don't
#      inherit the container's env vars (LIBVIRT_GATEWAY etc.) unless told
#      to via PassEnvironment — needed for %(ENV:...)s interpolation in
#      kvm.conf/routing.conf/auxiliary.conf to actually resolve instead of
#      raising configparser.InterpolationMissingOptionError.
#
#   4. This image ships its OWN libvirtd.service/.socket, enabled. Since
#      /var/run/libvirt is bind-mounted from the HOST (see docker-compose.yml),
#      both this image's libvirtd and the host's are racing to own the exact
#      same socket file — whichever one (re)creates it last wins, stamping
#      it with ITS OWN idea of the "libvirt" group's GID. That's the real
#      cause behind an otherwise-inexplicable flip-flop where the host's
#      socket kept alternating group ownership independent of anything done
#      host-side. Masking the image's own units (never needed — CAPE inside
#      this container talks to the HOST's libvirtd, not one of its own) is
#      the actual fix; the GID-matching step below is necessary but not
#      sufficient without this.
#
#   5. The image's baked-in "libvirt" group GID doesn't match the HOST's —
#      confirmed to differ in practice (122 in this image vs 126 on the
#      machine this was first deployed on), and there's no reason to expect
#      any two machines to agree, since it's just whatever number each
#      host's package manager happened to assign. The host's libvirt-sock
#      is bind-mounted in (see docker-compose.yml), and AF_UNIX permission
#      checks are purely numeric — a name match ("libvirt" == "libvirt")
#      means nothing if the GIDs disagree, so cape/cape-web/cape-processor
#      get a silent Permission Denied connecting to libvirt with no hint
#      that a GID mismatch is the cause. fix-libvirt-gid.sh realigns the
#      container's group to whatever this host's socket actually says, at
#      every service start (can't be done at build time — the host isn't
#      known yet).
#
#   6. Named volumes mounted over an existing image path don't reliably
#      inherit that path's ownership — /opt/CAPEv2/db (SQLite, the actual
#      task DB CAPE uses by default; see docker-compose.yml's volumes:
#      comment) was cape:cape in the image but came up root:root on first
#      use of its volume. Postgres/Mongo don't hit this since their own
#      startup scripts chown as root before dropping privileges; CAPE's own
#      units just exec straight as User=cape with no equivalent step.
#
#   7. This image ships CAPE's own bare core with only 8 signature files
#      total (mostly __init__.py package markers) — none of the real
#      detection content. CAPESandbox's actual signature/YARA-rule set
#      (600+ signatures, 650+ YARA rules) lives in a SEPARATE "community"
#      repo, pulled in via utils/community.py, which upstream's own
#      Dockerfile never runs. Confirmed in practice: a RoningLoader
#      detonation that visibly installed a kernel driver service scored
#      malscore 0 with zero signatures matched pre-fix; after installing
#      the community content and reprocessing the SAME captured data (no
#      re-detonation needed), 55 signatures matched including
#      install_kernel_driver_service, malscore 9.0. Installing at BUILD
#      time, not container-start: it's static content, not something that
#      needs to be network-fetched on every boot, and it means the sandbox
#      doesn't need outbound internet access at runtime to have real
#      detection content — worth keeping true for a sandbox that's
#      otherwise deliberately network-contained (see routing.conf).
#
# Update docker-compose.yml's cape service to `build: {context: ./cape}`
# instead of `image: cape:kvm` to use this.
# =============================================================================

FROM cape:kvm

# --- Fix 1: MongoDB kernel 6.19+ crash --------------------------------------
COPY mongodb-override.conf /etc/systemd/system/mongodb.service.d/override.conf

# --- Fix 2: libvirt-python missing in the poetry venv -----------------------
# cape:kvm (built from the fork, see header above) already installs
# libvirt-python into this exact venv at base-image build time — re-running
# that install here was redundant duplicate work, and on a flaky network
# it's one more thing that can fail for zero benefit. The verification
# further down (after the USER cape / WORKDIR switch) is what's left of
# this fix.
USER root

# --- Fix 3: none of CAPE's systemd units inherit container env vars needed
# for %(ENV:...)s interpolation in CAPE's conf files (LIBVIRT_GATEWAY etc.)
# — systemd units don't inherit PID 1's environment unless told to. This
# has to cover all three services, not just cape.service: cape-processor
# reads routing.conf/auxiliary.conf (inetsim gateway IP) when processing
# network artifacts, and cape-web reads the same machinery config for the
# submission form's route list.
RUN for svc in cape cape-web cape-processor; do \
        mkdir -p "/etc/systemd/system/${svc}.service.d"; \
    done

# --- Fix 4: this image's own libvirtd must never run ------------------------
# It's enabled by default, but CAPE inside this container is meant to talk to
# the HOST's libvirtd via the bind-mounted socket (see docker-compose.yml),
# not run one internally. Left enabled, the two race to own the same socket
# file at container boot and corrupt its ownership unpredictably. `mask`
# (not just `disable`) so nothing — not even another unit's dependency — can
# start it.
RUN systemctl mask libvirtd.service libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket

# --- Fix 5: this image's "libvirt" group GID won't match the host's ---------
COPY fix-libvirt-gid.sh /usr/local/bin/fix-libvirt-gid.sh
RUN chmod +x /usr/local/bin/fix-libvirt-gid.sh

# --- Fix 6: named volumes lose /opt/CAPEv2/db's cape:cape ownership --------
COPY fix-volume-ownership.sh /usr/local/bin/fix-volume-ownership.sh
RUN chmod +x /usr/local/bin/fix-volume-ownership.sh

# ExecStartPre's `+` prefix runs each line as root regardless of the unit's
# own User=cape — groupmod/chown both need privileges cape doesn't have.
#
# RestartSec=10s: cape.service's base unit uses the stock 5m backoff, meant
# for real crashes, not this. All three services' ExecStartPre fixups land
# within the same couple hundred ms of container boot, and cape.service has
# occasionally forked its main process a beat before they settled, crashing
# once on stale state — self-healing, but not inside 5 minutes. 10s means a
# fresh `docker compose up` recovers on its own well within the time it
# takes to notice, instead of needing a manual `systemctl restart` nudge.
RUN for svc in cape cape-web cape-processor; do \
        printf '[Service]\nExecStartPre=+/usr/local/bin/fix-libvirt-gid.sh\nExecStartPre=+/usr/local/bin/fix-volume-ownership.sh\nPassEnvironment=LIBVIRT_GATEWAY LIBVIRT_BRIDGE GUEST_VM_IP\nRestartSec=10s\n' \
            > "/etc/systemd/system/${svc}.service.d/override.conf"; \
    done

# Install into the SAME venv the systemd units actually invoke — confirmed
# via `systemctl cat cape-processor.service`: ExecStart uses
# /etc/poetry/bin/poetry run, working directory /opt/CAPEv2. Using
# `pip install` inside that venv rather than `poetry add` deliberately —
# this doesn't touch pyproject.toml/poetry.lock, which we don't want to
# perturb for an environment-compatibility fix that has nothing to do with
# the project's actual declared dependencies.
#
# USER/WORKDIR matter here beyond just "the right venv": poetry resolves
# its cache location from the CURRENT user's HOME, and running the same
# `poetry run` command as a different user (e.g. root, or via `docker exec`
# with no -u) silently creates/uses a SEPARATE venv at a different path —
# confirmed the hard way debugging fix 7's install below, chasing a string
# of "missing dependency" errors that were really just python packages
# installed into a venv nothing actually uses. USER cape here is what
# makes this land in the venv cape.service/cape-web.service/
# cape-processor.service actually invoke.
USER cape
WORKDIR /opt/CAPEv2

# Fail the BUILD, loudly, if this doesn't actually work — rather than
# produce an image that looks fine and only reveals the problem at runtime
# inside a systemd crash loop, which is exactly how we lost time on this
# earlier today.
RUN /etc/poetry/bin/poetry run python -c "import libvirt; print('libvirt-python OK:', libvirt.__file__)"

# --- Fix 7: real signature/YARA detection content -------------------------
# community.py needs urllib3, which (like libvirt-python above) isn't in
# this image's poetry install. -af = download everything (signatures,
# processing/reporting modules, machinery, YARA rules, MITRE data, etc.),
# -f = don't prompt for confirmation on each file.
RUN /etc/poetry/bin/poetry run pip install urllib3 && \
    /etc/poetry/bin/poetry run python utils/community.py -af

# Fail the BUILD, loudly, if this doesn't actually work — same reasoning as
# the libvirt-python check above.
RUN count=$(find /opt/CAPEv2/modules/signatures -name "*.py" -not -path "*__pycache__*" | wc -l) && \
    echo "signature files installed: $count" && \
    [ "$count" -gt 100 ]

USER root
