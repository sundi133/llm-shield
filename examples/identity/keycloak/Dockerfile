# Keycloak for the Shield identity demo, with the bank realm baked in.
#
# The realm is imported at boot, so the roles and demo users are version
# controlled rather than clicked into an admin console — a wiped database
# rebuilds identically instead of costing you the demo.
#
# Build context is THIS folder:
#     docker build -t shield-keycloak examples/identity/keycloak
#
# On Railway: Root Directory = examples/identity/keycloak, target port 8080.
# It needs a Postgres service and a public domain — Shield fetches JWKS from
# the internet, so this cannot stay on Railway's private network.

# Pre-build against Postgres so the container starts fast. A cold Keycloak that
# auto-builds on boot takes ~60s, which is a long time to stand on a stage.
FROM quay.io/keycloak/keycloak:26.0 AS builder
ENV KC_DB=postgres
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.0
COPY --from=builder /opt/keycloak/ /opt/keycloak/
COPY realm-bank.json /opt/keycloak/data/import/realm-bank.json

ENV KC_DB=postgres \
    KC_HTTP_PORT=8080 \
    KC_PROXY_HEADERS=xforwarded \
    KC_HOSTNAME_STRICT=false

EXPOSE 8080
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized", "--import-realm", "--http-enabled=true"]
