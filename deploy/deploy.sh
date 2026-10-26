#!/bin/sh
# Ship Cubby to Jinx. The box keeps its own checkout at /opt/apps/Cubby, so the
# unit of deployment is a fast-forward of that checkout, a rebuild in place and
# a restart of the `cubby` systemd unit. Nothing is copied from here, which is
# what makes a deploy from CI and a deploy from a laptop the same operation.
#
# --ff-only rather than a plain pull: if the checkout on the box has drifted,
# stop and say so rather than quietly merging something nobody wrote.
#
# The disk on Jinx is failing, so writes are kept down: the npm cache is on
# tmpfs (/tmp/npm, set in ~/.npmrc there) and dev dependencies are pruned once
# the build is done. Runtime config is /etc/apps/cubby.env, read by the unit.
set -eu
ssh ssh.futile.studio '
  set -eu
  cd /opt/apps/Cubby
  git pull --ff-only
  # Zero dependencies and no build step, so there is nothing to install.
  sudo -n systemctl restart cubby

  # Come back and check, rather than trusting that a restart meant "serving".
  sleep 5
  code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:4747/ || true)
  case "$code" in
    200) echo "cubby: serving on 127.0.0.1:4747 (HTTP $code)" ;;
    *) echo "cubby: not serving (HTTP $code)"; sudo -n journalctl -u cubby -n 30 --no-pager; exit 1 ;;
  esac
'
echo "cubby: deployed to https://cubby.futile.studio"
