#!/bin/sh
# A named volume mounted over an existing image path doesn't reliably
# inherit that path's ownership -- /opt/CAPEv2/db came up root:root on
# first use of the cape_task_db volume, breaking cape.service's SQLite
# access. CAPE's systemd units exec straight as User=cape with no chown
# step (unlike Postgres/MongoDB's own startup scripts), so this fills
# that gap, same as fix-libvirt-gid.sh. Runs via `ExecStartPre=+` (root).
set -e
chown -R cape:cape /opt/CAPEv2/db
