#!/bin/sh
# Aligns this container's "libvirt" group GID with the host's actual one.
# The bind-mounted libvirt-sock's GID is whatever the host assigned, with
# no guarantee it matches this image's baked-in GID; AF_UNIX permission
# checks are purely numeric, so a name match means nothing if the numbers
# disagree -- cape/cape-web/cape-processor get a silent Permission Denied
# otherwise. Runs via `ExecStartPre=+` (root) since groupmod needs
# privileges the cape user doesn't have.
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
