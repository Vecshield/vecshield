#!/bin/sh
# Seed the demo estate once, then serve the console.
#
# Idempotent: the seeder is skipped if /data already holds a seeded estate, so
# `docker compose up` after a stop resumes rather than rebuilding, and any
# triage you did in the console survives the restart.
set -eu

STATE=/data
CONFIG="$STATE/vecshield.json"
PASSWORD_FILE="$STATE/admin-password"

if [ ! -f "$CONFIG" ]; then
    echo "Seeding the demo estate (synthetic data, local Chroma, no network)..."
    # --strict: the seeder verifies that every scenario it advertises actually
    # fires, and fails rather than serving a demo that quietly stopped working.
    python /src/demo/seed.py --state "$STATE" --strict
else
    echo "Reusing the estate already seeded in $STATE."
    echo "To start over: docker compose down -v && docker compose up"
fi

# The server refuses to bind beyond localhost while the bootstrap admin still
# has the default password. Mint a strong one on first boot instead of shipping
# a known credential, and keep it so restarts do not change it.
if [ ! -f "$PASSWORD_FILE" ]; then
    python -c "import secrets; print(secrets.token_urlsafe(18))" > "$PASSWORD_FILE"
    chmod 600 "$PASSWORD_FILE"
fi
VECSHIELD_INITIAL_ADMIN_PASSWORD="$(cat "$PASSWORD_FILE")"
export VECSHIELD_INITIAL_ADMIN_PASSWORD

cat <<BANNER

  VecShield demo console
  ----------------------
  URL       http://127.0.0.1:8088
  Username  admin
  Password  $VECSHIELD_INITIAL_ADMIN_PASSWORD

  The password is generated on first boot and kept in the demo volume.
  Read it again with:  docker compose exec vecshield cat /data/admin-password

  All data in this estate is synthetic. Walkthrough: demo/WALKTHROUGH.md

BANNER

exec vecshield-platform serve \
    --config "$CONFIG" \
    --state-dir "$STATE/state" \
    --host 0.0.0.0 \
    --port 8088
