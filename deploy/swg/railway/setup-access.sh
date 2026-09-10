#!/usr/bin/env bash
# One-time setup so `railway ssh` works. Idempotent: safe to re-run.
#
#   ./deploy/swg/railway/setup-access.sh
#
# Four things have to be true before you can get a shell in a Railway service,
# and three of them fail with errors that do not say what to do:
#
#   railway ssh keys add        "No registered SSH keys found"
#   ssh host key not trusted    "Host key verification failed"
#   project not linked          "No linked project found"
#
# This does all four and tells you which ones it changed.
set -uo pipefail

PROJECT="${1:-votal-swg-testbed}"

ok()   { printf '  \033[32mok\033[0m    %s\n' "$1"; }
did()  { printf '  \033[33mdone\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mfail\033[0m  %s\n' "$1"; }

echo "Setting up railway ssh access"

# 1. the CLI
if ! command -v railway >/dev/null 2>&1; then
    fail "Railway CLI not installed."
    echo
    echo "    npm i -g @railway/cli          (or: brew install railway)"
    echo "    winget install Railway.RailwayCLI    on Windows"
    exit 1
fi
ok "CLI present ($(railway --version 2>/dev/null | head -1))"

# 2. logged in
if railway whoami >/dev/null 2>&1; then
    ok "logged in as $(railway whoami 2>/dev/null | sed 's/Logged in as //')"
else
    did "opening a browser to log in"
    railway login || { fail "login failed"; exit 1; }
fi

# 3. an SSH key Railway knows about
if railway ssh keys 2>/dev/null | grep -q "Fingerprint:"; then
    ok "SSH key already registered"
else
    if ! ls ~/.ssh/*.pub >/dev/null 2>&1; then
        did "no SSH key found, generating one"
        ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519 -C "$(whoami)@$(hostname)" >/dev/null
    fi
    railway ssh keys add --name "swg-testbed-$(hostname)" >/dev/null 2>&1 \
        && did "registered your SSH key with Railway" \
        || fail "could not register a key: run 'railway ssh keys add'"
fi

# 4. Railway's own host key, or ssh refuses non-interactively with
#    "Host key verification failed" and no hint about why
mkdir -p ~/.ssh && touch ~/.ssh/known_hosts
if ssh-keygen -F ssh.railway.com >/dev/null 2>&1; then
    ok "ssh.railway.com already trusted"
else
    ssh-keyscan -t ed25519,rsa ssh.railway.com 2>/dev/null >> ~/.ssh/known_hosts \
        && did "added ssh.railway.com to known_hosts" \
        || fail "ssh-keyscan failed; check network access to ssh.railway.com"
fi

# 5. linked to the project
if railway status >/dev/null 2>&1; then
    ok "linked to $(railway status 2>/dev/null | grep -i '^Project:' | sed 's/Project: *//')"
else
    did "linking to $PROJECT"
    railway link --project "$PROJECT" >/dev/null 2>&1 \
        || { fail "could not link automatically. Run: railway link"; exit 1; }
fi

echo
echo "Ready. Try it:"
echo
echo "  railway ssh -s demo-client"
echo
echo "then, in that shell:"
echo
echo "  curl -s http://shield-icap.railway.internal:8081/healthz"
echo
echo "Guided walkthrough: deploy/swg/railway/TRY-IT.md"
