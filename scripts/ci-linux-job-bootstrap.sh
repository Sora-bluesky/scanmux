#!/usr/bin/env bash
set -euo pipefail
umask 077
run=$1
image=$2
mkdir -- "$run/src" "$run/out"
tar --no-same-owner -xf /tmp/scanmux-linux-job-source.tar -C "$run/src"
chown -R 1000:1000 -- "$run"
# Private runtime bundles must be readable by the product's UID 1000.
exec python3 -I -B -c '
import os, sys
gid = os.stat("/var/run/docker.sock").st_gid
os.setgroups([gid])
os.setgid(1000)
os.setuid(1000)
os.execv("/usr/local/bin/node", ["node", sys.argv[1] + "/src/scripts/ci-linux-job-harness.mjs", sys.argv[1], sys.argv[2]])
' "$run" "$image"
