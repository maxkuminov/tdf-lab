#!/bin/sh
# =============================================================================
#  tdf-lab-web entrypoint: validate the runtime configuration, render
#  /tmp/tdf-lab/{config.js,default.conf}, then exec nginx in the foreground.
#
#  Environment (the whole deployment contract of this image):
#    TDF_PLATFORM_URL            required  https://platform.example.org
#    TDF_KEYCLOAK_URL            required  https://keycloak.example.org
#    TDF_KEYCLOAK_REALM          default   lab-realm
#    TDF_OIDC_CLIENT_ID          default   web-console
#    TDF_OIDC_WRAPPER_CLIENT_ID  default   wrapper
#    TDF_ATTRIBUTE_NAMESPACE     default   https://lab.example
#    TDF_SHARE_API_UPSTREAM      default   tdf-share-api:3000   (host:port)
#
#  Every value lands in JavaScript (config.js) and in nginx directives / the
#  CSP, so each is checked against a pattern with no quote, space, semicolon,
#  backslash or newline in its alphabet. Anything else refuses to start: a
#  crash-looping pod is the right outcome for a malformed value, not a page
#  that runs with it.
# =============================================================================
set -eu

fail() { echo "tdf-lab-web: $*" >&2; exit 64; }

# check NAME REGEX - the whole value must match, and it must be ONE line
# (grep -x matches per line, so a value with an embedded newline is refused
# before grep ever sees it).
check() {
  eval "v=\${$1-}"
  [ -n "$v" ] || fail "$1 is required"
  case "$v" in *'
'*) fail "$1 must be a single line" ;; esac
  printf '%s' "$v" | grep -Eqx "$2" || fail "$1 is malformed: must match $2"
}

ORIGIN='https://[A-Za-z0-9.-]+(:[0-9]{1,5})?'
IDENT='[A-Za-z0-9._-]{1,64}'

: "${TDF_KEYCLOAK_REALM:=lab-realm}"
: "${TDF_OIDC_CLIENT_ID:=web-console}"
: "${TDF_OIDC_WRAPPER_CLIENT_ID:=wrapper}"
: "${TDF_ATTRIBUTE_NAMESPACE:=https://lab.example}"
: "${TDF_SHARE_API_UPSTREAM:=tdf-share-api:3000}"

check TDF_PLATFORM_URL "$ORIGIN"
check TDF_KEYCLOAK_URL "$ORIGIN"
check TDF_ATTRIBUTE_NAMESPACE "$ORIGIN"
check TDF_KEYCLOAK_REALM "$IDENT"
check TDF_OIDC_CLIENT_ID "$IDENT"
check TDF_OIDC_WRAPPER_CLIENT_ID "$IDENT"
check TDF_SHARE_API_UPSTREAM '[A-Za-z0-9.-]+:[0-9]{1,5}'

# The /sealed/ CSP hash is a property of the BUILD, baked in by the Dockerfile.
# Read from the image, never from the environment.
TDF_SEALED_SCRIPT_HASH=$(cat /etc/tdf-lab/sealed-script.sha256)
check TDF_SEALED_SCRIPT_HASH 'sha256-[A-Za-z0-9+/]{43}='

export TDF_PLATFORM_URL TDF_KEYCLOAK_URL TDF_SHARE_API_UPSTREAM TDF_SEALED_SCRIPT_HASH

out=/tmp/tdf-lab
mkdir -p "$out"

# Only these names are substituted; nginx's own $host, $uri, $csp ... survive.
envsubst '${TDF_PLATFORM_URL} ${TDF_KEYCLOAK_URL} ${TDF_SHARE_API_UPSTREAM} ${TDF_SEALED_SCRIPT_HASH}' \
  < /etc/tdf-lab/default.conf.template > "$out/default.conf.tmp"
mv "$out/default.conf.tmp" "$out/default.conf"

# Values are validated above, so single-quoting them in JS is safe: none can
# contain a quote, a backslash or a line break.
cat > "$out/config.js.tmp" <<JS
// Rendered at container start by tdf-lab-web's entrypoint. Not a secret.
window.__TDF_LAB_CONFIG__ = Object.freeze({
  platformUrl: '${TDF_PLATFORM_URL}',
  keycloakUrl: '${TDF_KEYCLOAK_URL}',
  realm: '${TDF_KEYCLOAK_REALM}',
  clientId: '${TDF_OIDC_CLIENT_ID}',
  wrapperClientId: '${TDF_OIDC_WRAPPER_CLIENT_ID}',
  attributeNamespace: '${TDF_ATTRIBUTE_NAMESPACE}',
});
JS
mv "$out/config.js.tmp" "$out/config.js"

exec nginx -e /dev/stderr -c /etc/nginx/nginx.conf -g 'daemon off;'
