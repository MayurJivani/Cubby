#!/bin/sh
# One-time setup on the box: the Caddy site block that puts TLS in front of the
# container. Needs root, and is the only step that does — the container itself
# runs as an ordinary member of the docker group, from deploy/deploy.sh.
#
# Re-runnable: it replaces any previous cubby block rather than appending, so
# editing deploy/cubby.caddy and running this again is the way to change it.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
CADDY=/etc/caddy/Caddyfile

# Say so up front rather than dying halfway through copying the Caddyfile.
if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh edits $CADDY and reloads caddy, so it needs root:" >&2
  echo "  sudo sh $0" >&2
  exit 1
fi

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

echo "cubby: Caddyfile updated and reloaded (backup at $CADDY.bak)"
