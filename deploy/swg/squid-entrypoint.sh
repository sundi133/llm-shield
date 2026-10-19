#!/bin/sh
# Initialise the forged-certificate database, then run Squid in the foreground.
#
# The CA itself is NOT generated here. It is mounted read-only from the host so
# the private key stays where the operator put it and never lives inside an
# image or a container layer. See docs/swg-deployment.md.
set -eu

CA=/etc/squid/ssl/ca.pem
SSL_DB=/var/spool/squid/ssl_db

if [ ! -f "$CA" ]; then
    echo "FATAL: no CA at $CA" >&2
    echo "Generate one on the host first (docs/swg-deployment.md), then mount it." >&2
    exit 1
fi

# security_file_certgen refuses to run against an existing directory, so only
# initialise when the volume is genuinely empty.
if [ ! -d "$SSL_DB" ]; then
    /usr/lib/squid/security_file_certgen -c -s "$SSL_DB" -M 8MB
    chown -R proxy:proxy "$SSL_DB"
fi

mkdir -p /var/log/squid /var/spool/squid
chown -R proxy:proxy /var/log/squid /var/spool/squid 2>/dev/null || true

# Squid drops to cache_effective_user (proxy) and then cannot open the
# container's stdout, which is owned by root. Without this it dies at startup
# with "Cannot open '/dev/stdout' for writing" -- and logs are how an operator
# sees what is being inspected, so this is not optional.
chmod a+w /dev/stdout /dev/stderr 2>/dev/null || true

# AI inventory lists (docs/specs/ai-discovery.md, task 3): the discovery
# shipper writes them; until it does, a placeholder that matches nothing keeps
# squid.conf's file ACLs valid.
LISTS=/etc/squid/lists
mkdir -p "$LISTS"
for f in ai_hosts.txt blocked_hosts.txt; do
    [ -s "$LISTS/$f" ] || echo ".never-matches.invalid" > "$LISTS/$f"
done

# The discovery log goes to the shipper over UDP, so nothing is written to
# disk and a stopped shipper costs the proxy nothing. Only the time, client,
# host and user are sent; never a path or a query.
if [ -n "${SHIELD_DISCOVERY_LOG:-}" ]; then
    printf 'logformat shield_discovery %%ts %%>a %%ssl::>sni %%>rd %%un\naccess_log udp://%s logformat=shield_discovery buffer-size=1bytes\n' \
        "$SHIELD_DISCOVERY_LOG" > /etc/squid/discovery.conf
else
    echo "# AI discovery log off: set SHIELD_DISCOVERY_LOG=host:port of the shipper" > /etc/squid/discovery.conf
fi

# Reload when the shipper changes a list, after checking the new config parses.
(
    last=$(cat "$LISTS"/*.txt 2>/dev/null | cksum)
    while sleep "${SHIELD_LISTS_POLL_S:-30}"; do
        now=$(cat "$LISTS"/*.txt 2>/dev/null | cksum)
        [ "$now" = "$last" ] && continue
        last=$now
        if squid -k parse -f /etc/squid/squid.conf >/dev/null 2>&1; then
            # SIGHUP, not `squid -k reconfigure`: Squid runs as PID 1 here
            # (exec below), and -k refuses to signal a PID file that says 1.
            pid=$(cat /run/squid.pid 2>/dev/null || echo 1)
            kill -HUP "$pid" && echo "AI inventory lists changed; Squid reloaded" >&2
        else
            echo "AI inventory lists changed but the config no longer parses; keeping the running one" >&2
        fi
    done
) &

# Fail loudly on a bad config rather than half-starting.
squid -k parse -f /etc/squid/squid.conf

exec squid -N -d1 -f /etc/squid/squid.conf
