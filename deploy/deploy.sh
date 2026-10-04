#!/bin/sh
# Ship cubby to Jinx. There is no node on that box and no root in this script, so
# the unit of deployment is a container: the source goes over as a tarball, docker
# builds it there, and the old container is replaced.
#
# The pile lives in the named volume `cubby-data`, which is never touched here —
# rebuilding or rolling back does not lose what people have dropped.
#
# deploy/ is also unpacked to ~/cubby-setup, because install.sh needs root and
# root needs a path that exists. That is the only piece of this that outlives the
# run.
set -eu
cd "$(dirname "$0")/.."

tar czf - Dockerfile package.json src bin deploy | ssh ssh.futile.studio '
  set -eu
  tmp=$(mktemp -d)
  trap "rm -rf $tmp" EXIT
  tar xzf - -C "$tmp"

  rm -rf ~/cubby-setup
  cp -r "$tmp/deploy" ~/cubby-setup

  # The server password and the superuser key are generated on the box, once,
  # and never travel with the source. Read them with: cat ~/.cubby-secrets
  secrets="$HOME/.cubby-secrets"
  if [ ! -f "$secrets" ]; then
    ( umask 077
      printf "CUBBY_PIN=%s\nCUBBY_ADMIN_KEY=%s\n" \
        "$(openssl rand -base64 24 | tr -dc A-Za-z0-9 | cut -c1-16)" \
        "$(openssl rand -base64 64 | tr -dc A-Za-z0-9 | cut -c1-44)" > "$secrets" )
    echo "cubby: generated $secrets — cat it to get the password and superuser key"
  fi

  docker build -q -t cubby:latest "$tmp" >/dev/null
  docker rm -f cubby >/dev/null 2>&1 || true
  docker run -d \
    --name cubby \
    --restart unless-stopped \
    --read-only \
    --tmpfs /tmp \
    --memory 512m \
    --publish 127.0.0.1:4747:4747 \
    --volume cubby-data:/data \
    --env-file "$secrets" \
    --env CUBBY_HOURS=24 \
    --env CUBBY_MB=2048 \
    --env CUBBY_MAX_KEEP_HOURS=168 \
    cubby:latest >/dev/null

  # Come back and check, rather than trusting that "docker run" meant "serving".
  sleep 2
  code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:4747/)
  [ "$code" = "200" ] || { echo "cubby: not serving (HTTP $code)"; docker logs --tail 30 cubby; exit 1; }
  echo "cubby: $(docker ps --filter name=cubby --format "{{.Status}}"), serving on 127.0.0.1:4747"
  echo "cubby: installer staged at ~/cubby-setup/install.sh"
'
