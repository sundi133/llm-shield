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

# Fail loudly on a bad config rather than half-starting.
squid -k parse -f /etc/squid/squid.conf

exec squid -N -d1 -f /etc/squid/squid.conf
