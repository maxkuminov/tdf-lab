# syntax=docker/dockerfile:1
# =============================================================================
#  ghcr.io/maxkuminov/tdf-lab-share-api - the ciphertext-only file store.
#
#  Build:   docker build -t tdf-lab-share-api shareapi/
#
#  Configuration is environment only (no file, no secret): OIDC_ISSUER,
#  OIDC_AUDIENCE, OIDC_JWKS_URL (optional, derived from the issuer),
#  ALLOWED_AZP, DATA_DIR, PORT and the MAX_* quotas - see README.md.
#  Runs as uid 10001 with a read-only root filesystem; DATA_DIR (/data) is the
#  only thing it writes and must be a volume. HOME=/tmp for node's own needs.
# =============================================================================
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1
LABEL org.opencontainers.image.title="tdf-lab-share-api" \
      org.opencontainers.image.description="TDF Lab share API: stores sealed .tdf files, never plaintext" \
      org.opencontainers.image.licenses="MIT"
ENV NODE_ENV=production \
    HOME=/tmp \
    PORT=3000 \
    DATA_DIR=/data
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
 && npm cache clean --force \
 # npm itself (and its bundled deps) is not needed at runtime; dropping it
 # removes the largest source of scanner findings in the base image.
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /root/.npm \
 # /data owned by the runtime uid: a fresh named volume copies this ownership,
 # so no out-of-band chown is needed.
 && mkdir -p /data && chown 10001:10001 /data
COPY src/ ./src/
USER 10001:10001
VOLUME ["/data"]
EXPOSE 3000
CMD ["node", "src/server.js"]
