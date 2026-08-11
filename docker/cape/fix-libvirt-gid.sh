#!/bin/sh
# Aligns this container's "libvirt" group GID with the host's actual one.
# The host's /var/run/libvirt/libvirt-sock is bind-mounted in (see
# docker-compose.yml), but its numeric GID is whatever the HOST's package
# manager happened to assign when it created that system group — there's
# no guarantee it matches this image's baked-in libvirt GID (confirmed to
# differ in practice: 122 in this image vs 126 on the machine this was
# first deployed on). AF_UNIX socket permission checks are purely
# numeric, so a name match ("libvirt" == "libvirt") means nothing if the
# numbers disagree — cape/cape-web/cape-processor get a silent Permission
# Denied connecting to libvirt otherwise, with no hint that a GID
# mismatch is the cause.
#
# Runs via `ExecStartPre=+` (root, regardless of the unit's own User=cape)
# since groupmod needs privileges the cape user doesn't have.
set -e

SOCK=/var/run/libvirt/libvirt-sock
for i in $(seq 1 30); do
    [ -S "$SOCK" ] && break
    sleep 1
done
[ -S "$SOCK" ] || { echo "fix-libvirt-gid: $SOCK never appeared after 30s, skipping" >&2; exit 0; }

HOST_GID=$(stat -c '%g' "$SOCK")
CONTAINER_GID=$(getent group libvirt | cut -d: -f3)
if [ "$HOST_GID" != "$CONTAINER_GID" ]; then
    groupmod -g "$HOST_GID" libvirt
fi
