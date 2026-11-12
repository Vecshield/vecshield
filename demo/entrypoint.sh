#!/bin/sh
# Seed the demo estate once, then serve the console.
#
# Idempotent: the seeder is skipped if /data already holds a seeded estate, so
# `docker compose up` after a stop resumes rather than rebuilding, and any
# triage you did in the console survives the restart.
set -eu

STATE=/data
CONFIG="$STATE/vecshield.json"

# A fixed, memorable credential, because this estate is synthetic and the
# console is published on loopback only. Override with VECSHIELD_DEMO_PASSWORD.
# It must be at least 12 characters and must not be one of the obvious choices
# ("admin", "password", "vecshield"), which the password policy refuses.
DEMO_PASSWORD="${VECSHIELD_DEMO_PASSWORD:-vecshield-demo}"

if [ ! -f "$CONFIG" ]; then
    echo "Seeding the demo estate (synthetic data, local Chroma, no network)..."
    # --strict: the seeder verifies that every scenario it advertises actually
    # fires, and fails rather than serving a demo that quietly stopped working.
    python /src/demo/seed.py --state "$STATE" --strict
else
    echo "Reusing the estate already seeded in $STATE."
    echo "To start over: docker compose down -v && docker compose up"
fi

# Create the admin account up front, and do its first-sign-in password change
# here rather than making you do it in the browser.
#
# The product always marks a freshly bootstrapped admin "must change password",
# which is right for a real deployment and pure friction for a demo you may
# reset several times an hour. This clears it the same way a person would --
# through the public change_password API, from a throwaway bootstrap password
# to the demo one -- so nothing about the product's own rules is bypassed or
# patched out.
python - "$CONFIG" "$STATE/state" "$DEMO_PASSWORD" <<'PY'
import secrets
import sys

from vecshield_platform.api.state import resolve_state_paths
from vecshield_platform.api.users import UserStore

config_path, state_dir, demo_password = sys.argv[1], sys.argv[2], sys.argv[3]
users_db = resolve_state_paths(config_path, state_dir).users_db

throwaway = secrets.token_urlsafe(24)
store = UserStore(users_db, initial_admin_password=throwaway)
try:
    admin = store.get_user("admin")
    if admin is not None and admin.must_change_password:
        store.change_password("admin", throwaway, demo_password)
        print("Admin account ready; the first-sign-in password change is done.")
    else:
        # A previous run already set it, or someone changed it deliberately.
        print("Admin account already set up; leaving its password alone.")
finally:
    store.close()
PY

cat <<BANNER

  VecShield demo console
  ----------------------
  URL       http://127.0.0.1:8088
  Username  admin
  Password  $DEMO_PASSWORD

  This is a published, well-known demo password, and the estate behind it is
  entirely synthetic. Compose publishes the console on 127.0.0.1 only. Do not
  bind this container to a public address, and do not reuse these settings for
  a real deployment -- see docs/deployment.md for that.

  Change it with:  VECSHIELD_DEMO_PASSWORD=... docker compose up

  Walkthrough: demo/WALKTHROUGH.md

BANNER

exec vecshield-platform serve \
    --config "$CONFIG" \
    --state-dir "$STATE/state" \
    --host 0.0.0.0 \
    --port 8088
