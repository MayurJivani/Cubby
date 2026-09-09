#!/bin/sh
# One-time setup on the box: the systemd unit and the Caddy site block. Needs
# root, and is the only step that does. Re-runnable — it replaces both rather
# than appending, so editing deploy/cubby.service or deploy/cubby.caddy and
# running this again is the way to change the deployment.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
CADDY=/etc/caddy/Caddyfile

install -d -m 755 /opt/apps/Cubby
install -m 644 "$HERE/cubby.service" /etc/systemd/system/cubby.service
systemctl daemon-reload
systemctl enable cubby

cp "$CADDY" "$CADDY.bak"

python3 - "$CADDY" "$HERE/cubby.caddy" <<'PY'
import pathlib, re, sys

caddy, block = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
# Drop any existing cubby block. It has one level of nesting (reverse_proxy), so
# match to a line-initial "}" — and validate below is the backstop.
text = re.sub(r"\n*http://cubby\.futile\.studio\s*\{.*?\n\}\n?", "\n", caddy.read_text(), flags=re.S)
caddy.write_text(text.rstrip() + "\n\n" + block.read_text())
PY

# Validate before reloading: this file serves every other site on the box.
caddy validate --adapter caddyfile --config "$CADDY"
systemctl reload caddy

echo "cubby: unit installed and Caddyfile reloaded (backup at $CADDY.bak)"
echo "cubby: now run deploy/deploy.sh to ship the code, then 'systemctl start cubby'"
