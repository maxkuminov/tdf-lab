# syntax=docker/dockerfile:1
# =============================================================================
#  ghcr.io/maxkuminov/tdf-lab-web - the TDF Lab Console (static SPA) behind
#  nginx, plus the same-origin /api/ proxy to the share API.
#
#  Build from the REPO ROOT:   docker build -f web/Dockerfile -t tdf-lab-web .
#
#  Nothing deployment-specific is baked in. The platform/Keycloak URLs, realm,
#  client ids and share-API upstream arrive as env vars at start (see
#  web/entrypoint.sh); the only build-derived value is the /sealed/ CSP hash.
#  Runs as uid 101 on :8080 with a read-only root filesystem - only /tmp must
#  be writable (emptyDir / tmpfs).
# =============================================================================

FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS build
WORKDIR /src
COPY webapp/package.json webapp/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY webapp/ ./
# records.json / config.js in public/ are local-only (gitignored, and excluded
# by .dockerignore); make sure neither can ride into the image.
RUN rm -f public/records.json public/config.js \
 && npm run typecheck \
 && npm run build \
 && test -s src/wrapper/generated/sealed-script.sha256 \
 && ! test -e dist/config.js

FROM nginxinc/nginx-unprivileged:1.30-alpine@sha256:ed04ec1ff34502c339ee5c3ae3f855442398edc1d05591e2b98981dcbbd20b1e
LABEL org.opencontainers.image.title="tdf-lab-web" \
      org.opencontainers.image.description="TDF Lab Console: static SPA + same-origin /api/ proxy, runtime-configured" \
      org.opencontainers.image.licenses="MIT"
USER root
# The stock server block is replaced wholesale; remove it so nothing can
# include it by accident. Everything below is root-owned and read-only to 101.
# `apk upgrade`: the base is pinned by digest for reproducibility, but Alpine
# ships fixes faster than the image is rebuilt; the Trivy gate fails on any
# HIGH/CRITICAL with a fix, so take the fixes at build time.
RUN apk upgrade --no-cache \
 && rm -f /etc/nginx/conf.d/default.conf \
 && mkdir -p /srv/tdf-lab/records /srv/tdf-lab/sealed /etc/tdf-lab
COPY web/nginx.conf /etc/nginx/nginx.conf
COPY web/default.conf.template /etc/tdf-lab/default.conf.template
COPY --chmod=0755 web/entrypoint.sh /usr/local/bin/tdf-lab-web-entrypoint
COPY --from=build /src/src/wrapper/generated/sealed-script.sha256 /etc/tdf-lab/sealed-script.sha256
COPY --from=build /src/dist/ /usr/share/nginx/html/
USER 101:101
EXPOSE 8080
STOPSIGNAL SIGQUIT
ENTRYPOINT ["/usr/local/bin/tdf-lab-web-entrypoint"]
