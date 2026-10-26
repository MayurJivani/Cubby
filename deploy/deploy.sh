#!/bin/sh
# Ship Cubby to Jinx. The box keeps its own checkout at /opt/apps/Cubby, so
# the unit of deployment is a fast-forward of that checkout, a rebuild in
# place and a restart of the `cubby` systemd unit. The code is not copied from
# here, which is what makes a deploy from CI and a deploy from a laptop the
# same operation; only deploy/cubby.service and deploy/cubby.caddy go over
# from this tree.
#
# --ff-only rather than a plain pull: if the checkout on the box has drifted,
# stop and say so rather than quietly merging something nobody wrote.
#
# Re-runnable, and the first run on an empty box sets everything up: the
# clone, the unit, the site block. Dev dependencies are pruned once the build
# is done. The public hostname is a Cloudflare dashboard step: Zero Trust >
# Tunnels > Public Hostname, cubby.futile.studio -> http://localhost:80.
set -eu
cd "$(dirname "$0")/.."
HOST=${HOST:-ssh.futile.studio}
NAME=cubby
SITE=cubby.futile.studio

scp -q deploy/cubby.caddy deploy/$NAME.service "$HOST":/tmp/
ssh "$HOST" "NAME=$NAME SITE=$SITE sh -s" <<'BOX'
set -eu
if ! cmp -s "/tmp/$NAME.service" "/etc/systemd/system/$NAME.service"; then
  sudo -n install -m 644 "/tmp/$NAME.service" "/etc/systemd/system/$NAME.service"
  sudo -n systemctl daemon-reload
  sudo -n systemctl enable -q "$NAME"
fi
rm -f "/tmp/$NAME.service"

LIVE=/etc/caddy/conf.d/cubby.caddy
IN=/tmp/cubby.caddy
if cmp -s "$IN" "$LIVE"; then
  rm -f "$IN"
else
  # Imported into the config serving every site: validate, and restore on failure.
  sudo -n cp "$LIVE" "$IN.prev" 2>/dev/null || true
  sudo -n install -m 644 "$IN" "$LIVE" && rm -f "$IN"
  if ! caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
    if [ -f "$IN.prev" ]; then sudo -n mv "$IN.prev" "$LIVE"; else sudo -n rm -f "$LIVE"; fi
    echo "$NAME: site block rejected by caddy validate, config unchanged" >&2
    exit 1
  fi
  sudo -n rm -f "$IN.prev"
  sudo -n systemctl reload caddy
fi

[ -d /opt/apps/Cubby/.git ] || git clone -q https://github.com/MayurJivani/Cubby.git /opt/apps/Cubby
cd /opt/apps/Cubby
git pull -q --ff-only
# Zero dependencies and nothing to build.
sudo -n systemctl restart "$NAME"

# Come back and check through Caddy, rather than trusting that a restart meant "serving".
for _ in $(seq 1 30); do
  curl -sf -o /dev/null -H "Host: $SITE" http://127.0.0.1/ && break
  sleep 1
done
curl -sf -o /dev/null -H "Host: $SITE" http://127.0.0.1/ || {
  echo "$NAME: not serving through Caddy"; sudo -n journalctl -u "$NAME" -n 30 --no-pager; exit 1
}
BOX
echo "$NAME: deployed to https://$SITE"
