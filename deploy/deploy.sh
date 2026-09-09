#!/bin/sh
# Ship cubby to Jinx. No build step and no dependencies, so this is a tarball and
# a restart. One-time setup is deploy/install.sh, which needs root; this does not,
# beyond the one systemctl call.
#
# The old copy is removed rather than written over: unlinking needs write on the
# directory and not on the file, so this still works when a previous deploy left
# root-owned files behind. cubby-data is never touched — the pile lives in
# /var/lib/cubby, outside the deploy tree.
set -eu
cd "$(dirname "$0")/.."
tar czf - src bin deploy package.json README.md | ssh ssh.futile.studio '
  set -eu
  cd /opt/apps/Cubby
  rm -rf ./src ./bin ./deploy ./package.json ./README.md
  tar xzf -
  sudo systemctl restart cubby
  sleep 1
  systemctl is-active --quiet cubby && echo "cubby: restarted" || { journalctl -u cubby -n 20 --no-pager; exit 1; }
'
