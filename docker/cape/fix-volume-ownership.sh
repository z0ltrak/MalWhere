#!/bin/sh
# Named volumes mounted over an existing image path don't reliably inherit
# that path's ownership — confirmed in practice: /opt/CAPEv2/db was
# cape:cape in the image, but came up root:root on first use of the
# cape_task_db volume (see docker-compose.yml), breaking cape.service's
# SQLite access with a generic "unable to open database file" (no
# permission-denied wording, so it wasn't obvious at first). Postgres and
# MongoDB don't hit this: their own startup scripts run as root and chown
# their data directory before dropping privileges. CAPE's own systemd
# units don't have an equivalent step — they exec straight as User=cape —
# so this fills that gap, the same way fix-libvirt-gid.sh fills the GID
# one. Runs via `ExecStartPre=+` (root, regardless of the unit's own
# User=cape).
set -e
chown -R cape:cape /opt/CAPEv2/db
