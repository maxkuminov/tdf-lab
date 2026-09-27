# tdf-lab

A small, self-hosted lab for learning the OpenTDF / ZTDF protected-data format
by running it: the OpenTDF platform (policy, authorization, Key Access Server),
Keycloak as the identity provider, a browser console, a ciphertext-only file
share, a self-decrypting HTML wrapper, and a field-level encrypted database
demo.

The write-up that goes with it is in [`docs/WHITEPAPER.md`](docs/WHITEPAPER.md).

Author: Max Kuminov, CISSP. Built as a personal homelab project,
2026-08-27 to 2026-09-01.

## The premise: possession is not access

There are two broad ways to control who reads a piece of data.

- **Mediated access.** The data stays behind a service, and every request goes
  through a policy decision point. Access control is only as good as your
  ability to keep every copy behind that service.
- **Cryptographic wrapping.** The data is encrypted into a container that
  carries its own policy (a TDF). The container can be copied anywhere. Reading
  it still requires a key rewrap from a Key Access Server (KAS), which checks
  the reader's entitlements against the policy bound into the file, at the
  moment of opening.

This lab is built to make the second model concrete and to show where it
still depends on the first. Every signed-in account can list and download every
sealed file in the share; that is deliberate. The bytes are inert until the KAS
agrees to rewrap the key for a specific reader. The interesting parts are the
boundary conditions: what the KAS can and cannot see, what happens when policy
changes after a file was sealed, and what it costs to make a file that can
decrypt itself away from any web application.

## What each component demonstrates

| Component | Where | What it shows |
|---|---|---|
| Platform stack | `docker-compose.yml`, `opentdf.yaml`, `keycloak_data.example.yaml`, `postgres-init/` | OpenTDF platform v0.25.1 in `mode: all` (policy, authorization, KAS, entity resolution), Keycloak, PostgreSQL, on an internal Docker network with no gateway. One attribute (`classification`, values `secret` and `public`) and two demo users who differ only in that attribute. |
| Web console | `webapp/`, `web/` | A React SPA that signs in with authorization code + PKCE, encrypts a file to an attribute in the browser, and shows the rewrap being allowed or denied. It draws a live protocol sequence diagram, dissects the manifest field by field, and distinguishes four refusals: policy denial, policy-binding mismatch (tamper), payload integrity failure, and token rejection. |
| Share API and Library | `shareapi/` (Express 5 + jose), Library panel in the console | The untrusted half of the lab. It stores sealed `.tdf` files and metadata, validates that uploads are well-formed TDFs, and never sees plaintext, a data key, or a password. Anyone signed in can fetch any file. Only the KAS decides who can read one. |
| Self-decrypting HTML wrapper | `webapp/src/wrapper/` | Any sealed file can be exported as one self-contained `.html` page carrying the ciphertext, the manifest, and a reader with the OpenTDF SDK inlined. The intended flow from disk signs in with the OAuth 2.0 Device Authorization Grant (RFC 8628, no redirect URI needed) and asks the KAS to rewrap. The pieces were tested separately; the full approval-to-plaintext chain remains unverified. The page states its two costs to the reader (see "Design trade-offs"). |
| Field-level encrypted SQLite | `dbdemo/dbdemo.py`, Database panel in the console | An `employees` table whose sensitive columns exist only as ZTDF ciphertexts, one TDF per cell, sealed under each row's classification. Plain columns stay queryable. Each protected cell costs one KAS rewrap to read, and an unentitled user gets a policy denial from the KAS, not a client-side check. All data is fictional. |
| NanoTDF note | `dbdemo/dbdemo.py` docstring | The per-cell demo was designed for NanoTDF, the compact binary TDF. NanoTDF was removed from OpenTDF in the v0.12.0 releases of 2026-01-27 (platform PR #3013, `fix!: remove nanotdf support`), covering the KAS rewrap path, the Go SDK, `otdfctl`, and the spec docs. The release notes identify this as a breaking change. So the demo uses standard ZTDF per cell and pays for it in size. The lab's console reported about 1.7 KB per sealed cell for fixture values of 8 to 30 bytes; `dbdemo.py sizes` prints the ratio for your own run. |

### Observations from running it

These were observed in the lab and are the reason the components exist. They
are not benchmarks.

- **Entitlements were not carried in the token.** The demo user's access token
  contained no `classification` claim. The entity resolution service read the
  attribute from Keycloak at each decision. Changing the attribute in Keycloak
  flipped the same, already-issued token from denied to allowed within about a
  second, and back again, with no re-login and no restart. The decision is made
  at open time against live state.
- **A rewrap refusal is not a transport error.** On platform v0.25.1 the KAS
  answers HTTP 200 with a per-key-access-object result carrying the error, and
  the SDK then throws. A client that watches only for failed HTTP calls records
  a denial as a success.
- **A `secret`-holder could read `public` data only because of a second
  subject mapping.** Without a mapping that grants `public`, a file sealed to
  `public` is readable by nobody, including the account that sealed it.
- **Possession did not grant access.** In the share, the unentitled user could
  list and download the entitled user's file byte-for-byte and still received
  a policy denial on rewrap.

## Design trade-offs

These are choices a lab can make and a production system should examine.

- **Allowing `Origin: null` in the platform's CORS list.** A document opened
  from `file://` reports the origin `null`, so a self-decrypting wrapper can
  only call the KAS if `null` is allowed. But `null` is not "this file". It is
  the origin of every file-loaded document and sandboxed frames without same-origin privileges. A
  deployment that allows it accepts cross-origin reads of platform responses
  from any opaque-origin page, in exchange for a wrapper that works with no web
  origin at all. A valid bearer token is still required, and no policy decision
  changes; what grows is the set of pages allowed to ask. The entry is marked
  in `opentdf.yaml`; delete it if you do not use wrappers.
- **The wrapper's own code handles the reader's token and plaintext.** In the
  console, the code is served by the lab. In a wrapper, it arrives in the same
  file as the ciphertext, from whoever sent it. Opening one is choosing to run
  the sender's program. Serving the reader from a trusted web origin avoids that particular code-delivery risk.
  The page and the console both say so next to the controls that produce one.
- **The `wrapper` client has no redirect URIs and only the device grant.** Its
  `webOrigins` is the literal `"null"` so a `file://` page can read the device
  and token responses. It is separate from `web-console` so the console's
  client never had to be loosened.
- **The `cli` client allows the OAuth password grant.** It is the mechanism used here to get a *user* token for scripted allow/deny checks. Acceptable for a
  lab with demo accounts; not something to copy.
- **The CSP for `/sealed/` pins one inline script by SHA-256.** A wrapper loads
  nothing else, so the single hash is the whole script policy. The runtime
  carries no hostname (each wrapper's metadata names its lab), so the hash is
  a property of the build alone: the web image computes it while building and
  pins it for you.

## Running it

This is a reference deployment, not a one-command quickstart. The platform must
fetch Keycloak's OIDC metadata at the same public issuer URL that appears in
users' tokens, so the stack assumes:

- Docker with Compose v2, on a host where you can create a custom bridge
  network (the network option below was tested on Docker 29.x);
- an existing reverse proxy (the compose labels are for Traefik) that
  terminates TLS with a certificate browsers trust, routes the three hostnames
  in `.env`, and joins `lab-net` with network aliases for
  `platform.lab.example` and `keycloak.lab.example` so that in-network lookups
  of those names reach the proxy (the "hairpin");
- DNS for the three hostnames;
- `otdfctl` (the OpenTDF CLI, from the platform releases page) and Python 3 for
  the command-line demos.

Replace `*.lab.example` everywhere with your own names: `.env`,
`opentdf.yaml`, `keycloak_data.yaml`. The console and the share API take
theirs from `.env` at container start (see "Container images"); nothing is
compiled in.
The policy namespace `lab.example` (in attribute FQNs such as
`https://lab.example/attr/classification/value/secret`) is an identifier inside
the policy model, not a host, and does not need to resolve.

**1. Config from the examples.**

```sh
cp .env.example .env && chmod 600 .env
cp keycloak_data.example.yaml keycloak_data.yaml && chmod 600 keycloak_data.yaml
# Replace every CHANGE_ME in both files. Client secrets and user passwords must
# match between the two, because `provision keycloak` does no substitution.
```

**2. KAS keys.** Generate them locally; they are never committed.

```sh
mkdir -m 700 keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/kas-private.pem
openssl pkey -in keys/kas-private.pem -pubout -out keys/kas-cert.pem
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -subj "/CN=kas" -days 365 -keyout keys/kas-ec-private.pem -out keys/kas-ec-cert.pem
chmod 600 keys/*-private.pem
```

`kas-cert.pem` is a bare RSA public key, which the platform accepts in place
of an X.509 certificate. The post-quantum hybrid keys in upstream's example
config are omitted; they need the platform's own keygen tool.

**3. The isolated network.** `internal: true` alone still leaves the host
reachable on the bridge gateway address; `gateway_mode_ipv4=isolated` removes
the gateway.

```sh
docker network create --driver bridge --internal \
  --opt com.docker.network.bridge.gateway_mode_ipv4=isolated lab-net
docker network inspect lab-net   # expect no Gateway in the IPAM config
```

Then attach your reverse proxy to `lab-net` with the two aliases.

**4. The console and share-API images.** Either pull the published ones or
build them from this checkout; no node is needed on the host either way.

```sh
docker compose pull tdf-console tdf-share-api    # ghcr.io/maxkuminov/tdf-lab-*
# or
docker compose build tdf-console tdf-share-api   # from web/ and shareapi/
```

A fresh `lab_sharedata` volume takes its ownership from the image (uid
10001). One created by an earlier version of this kit (uid 1000) needs a
one-off `docker run --rm -v lab_sharedata:/data alpine chown -R 10001:10001 /data`.

**5. The wrapper CSP needs nothing.** The `/sealed/` script hash is computed
while the web image is built and substituted at start; there is no hash to
paste.

**6. Bring it up.**

```sh
docker compose up -d
docker compose logs -f tdf-provision-keycloak   # one-shot: creates the realm, exits 0
curl -fsS https://platform.lab.example/healthz  # expect {"status":"SERVING"}
```

`provision keycloak` creates objects but never updates them, and still exits
0. Editing `keycloak_data.yaml` against an existing realm changes nothing; the
only reset is `docker compose down -v`, which destroys both databases. After a
fresh `up`, confirm a client-credentials grant against `entity-resolution`
works and that its token's `aud` contains `https://platform.lab.example` before
chasing any later authorization error.

**7. Seed the policy** (as the `platform-admin` service account, which has the
`opentdf-admin` realm role):

```sh
set -a; . ./.env; set +a
otdf() {
  otdfctl --host "https://${TDF_PLATFORM_HOST}" \
    --with-client-creds '{"clientId":"platform-admin","clientSecret":"'"$CLIENT_SECRET_PLATFORM_ADMIN"'"}' "$@"
}
jid() { python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])'; }

otdf policy kas-registry create --uri "https://${TDF_PLATFORM_HOST}/kas" --name lab-kas

NS_ID=$(otdf policy attributes namespaces create --name lab.example --json | jid)
ATTR_ID=$(otdf policy attributes create --namespace "$NS_ID" --name classification --rule ANY_OF --json | jid)
VAL_SECRET=$(otdf policy attributes values create --attribute-id "$ATTR_ID" --value secret --json | jid)
VAL_PUBLIC=$(otdf policy attributes values create --attribute-id "$ATTR_ID" --value public --json | jid)

# operator 1 = IN, boolean_operator 1 = AND
scs() { printf '[{"condition_groups":[{"boolean_operator":1,"conditions":[{"operator":1,"subject_external_selector_value":".attributes.classification[]","subject_external_values":%s}]}]}]' "$1"; }
otdf policy subject-mapping create --attribute-value-id "$VAL_SECRET" --action read --action create \
  --subject-condition-set-new "$(scs '["secret"]')"
otdf policy subject-mapping create --attribute-value-id "$VAL_PUBLIC" --action read --action create \
  --subject-condition-set-new "$(scs '["public","secret"]')"
```

The KAS must be registered before `otdfctl decrypt` will use it. The second
mapping makes `public` readable by both levels, which turns one attribute and
two mappings into a two-level hierarchy.

**8. Allow and deny.** The demo users need user tokens; the `cli` client's
password grant gets them headlessly.

```sh
tok() { curl -fsS "https://${TDF_KEYCLOAK_HOST}/realms/lab-realm/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=cli -d "username=$1" -d "password=$2" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])'; }
A=$(tok user-a "$USER_A_PASSWORD"); B=$(tok user-b "$USER_B_PASSWORD")
FQN=https://lab.example/attr/classification/value/secret
P="https://${TDF_PLATFORM_HOST}"

echo "a test message" > /tmp/lab.txt
otdfctl --host "$P" --with-access-token "$A" encrypt /tmp/lab.txt --attr "$FQN" --out /tmp/lab.txt.tdf
otdfctl --host "$P" --with-access-token "$A" decrypt /tmp/lab.txt.tdf   # allowed
otdfctl --host "$P" --with-access-token "$B" decrypt /tmp/lab.txt.tdf   # permission denied, not a 401
```

To flip `user-b`, set its `classification` attribute to `secret` in the
Keycloak admin console (realm `lab-realm`, Users) and re-run the last command
with the same token. If you use the Admin API instead, PUT the user's full
representation: a PUT carrying only `attributes` returns 204 and clears the
user's email and name, after which the password grant fails with "Account is
not fully set up".

**9. The console and the database demo.** Open `https://tdf.lab.example`, sign
in as either user, and use Encrypt, Decrypt, Library, and Database. For the
Database panel, generate the sealed table first:

```sh
python3 dbdemo/dbdemo.py seed          # seal the fixture rows as user-a
python3 dbdemo/dbdemo.py view user-a   # every cell decrypts
python3 dbdemo/dbdemo.py view user-b   # secret rows come back DENIED
python3 dbdemo/dbdemo.py sizes         # per-cell ciphertext overhead
python3 dbdemo/dbdemo.py export        # writes webapp/public/records.json
```

`records.json` and `records.sqlite` are generated and gitignored. Until you
run `export`, the Database panel has nothing to load.

## Container images

Two images are built from this repo by `.github/workflows/image.yml` (Trivy
gated: any HIGH/CRITICAL with a fix fails the build) and published to GHCR
with `sha-<commit>` tags, `latest` from `main`, and the tag name for `v*`
tags. Pin by digest for anything you keep. Neither image contains a secret,
a hostname or any deployment-specific value.

### `ghcr.io/maxkuminov/tdf-lab-web`

The console SPA plus the same-origin `/api/` proxy to the share API
(`web/Dockerfile`, nginx-unprivileged). Listens on **8080** as **uid 101**,
and runs with a **read-only root filesystem**: only `/tmp` must be writable
(a tmpfs / `emptyDir`). At start, `web/entrypoint.sh` validates its
environment, renders `/config.js` (read by the SPA before it boots) and the
nginx server block (CSP `connect-src`/`form-action`, `/api/` upstream) into
`/tmp`, and refuses to start on any malformed value.

| Variable | Required | Default | Shape |
|---|---|---|---|
| `TDF_PLATFORM_URL` | yes | | `https://host[:port]` |
| `TDF_KEYCLOAK_URL` | yes | | `https://host[:port]` (Keycloak at its root path) |
| `TDF_KEYCLOAK_REALM` | | `lab-realm` | `[A-Za-z0-9._-]{1,64}` |
| `TDF_OIDC_CLIENT_ID` | | `web-console` | same |
| `TDF_OIDC_WRAPPER_CLIENT_ID` | | `wrapper` | same |
| `TDF_ATTRIBUTE_NAMESPACE` | | `https://lab.example` | `https://host[:port]` |
| `TDF_SHARE_API_UPSTREAM` | | `tdf-share-api:3000` | `host:port`, resolvable when nginx starts |

The KAS URL is `$TDF_PLATFORM_URL/kas` and must match the KAS registry entry
exactly.

Optional read-only mounts:

- `/srv/tdf-lab/records/records.json`: the Database panel's sealed table
  (`python3 dbdemo/dbdemo.py export` writes it to `webapp/public/`, which the
  Compose file mounts here). It is about 36 KB, so on Kubernetes a ConfigMap
  with the key `records.json` mounted at `/srv/tdf-lab/records` is enough.
  Without it `/records.json` is 404 and the panel says there is no table.
- `/srv/tdf-lab/sealed/`: self-decrypting wrappers to serve under `/sealed/`.

Probes: `GET /healthz` on 8080 (unauthenticated, unlogged).

### `ghcr.io/maxkuminov/tdf-lab-share-api`

The ciphertext-only store (`shareapi/Dockerfile`, node 24 alpine, production
dependencies only, npm removed). Listens on **3000** as **uid 10001** with a
**read-only root filesystem** (`HOME=/tmp`; mount a tmpfs / `emptyDir` at
`/tmp`). `DATA_DIR` (default `/data`) is the only thing it writes and must be
a persistent volume writable by uid 10001 (on Kubernetes, `fsGroup: 10001`).

| Variable | Required | Default |
|---|---|---|
| `OIDC_ISSUER` | yes | (must equal the tokens' `iss`, e.g. `https://keycloak.lab.example/realms/lab-realm`) |
| `OIDC_AUDIENCE` | yes | (the platform URL the audience mapper injects) |
| `OIDC_JWKS_URL` | | `$OIDC_ISSUER/protocol/openid-connect/certs` |
| `ALLOWED_AZP` | | `web-console,cli` |
| `DATA_DIR` | | `/data` |
| `PORT` | | `3000` |
| `MAX_FILE_BYTES` / `MAX_FILES_PER_USER` / `MAX_BYTES_PER_USER` | | 20 MiB / 50 / 200 MiB |

Probes: `GET /healthz` on 3000. It returns a file count, so expose the service
only to the web pod; the web image already answers `/api/healthz` with 404.

### Kubernetes notes

Both images are meant for `runAsNonRoot: true`, `readOnlyRootFilesystem: true`,
`allowPrivilegeEscalation: false` and `capabilities: {drop: [ALL]}`, with an
`emptyDir` at `/tmp`. Point `TDF_SHARE_API_UPSTREAM` at the share API's
Service. Run one share-API replica: its index is a single JSON file on the
volume. The platform, Keycloak and PostgreSQL stay on their upstream images.

### Local development

`npm run dev` in `webapp/` needs a config: copy `webapp/config.example.js` to
`webapp/public/config.js` (gitignored) and set your hostnames.

### Verification harnesses

`webapp/e2e/` holds three checks that were run against the lab and are kept
for reference rather than as a turnkey suite:

- `e2e.ts` (`npm run verify:headless`) drives the same source modules the SPA
  ships, from Node, with `USER_A_TOKEN` / `USER_B_TOKEN` in the environment
  (and the deployment in `TDF_PLATFORM_URL`, `TDF_KEYCLOAK_URL`,
  `TDF_APP_ORIGIN` etc.; see `e2e/config-shim.ts`). It
  also reads several `/tmp/*.tdf` fixtures (tampered, truncated, structurally
  fake, a plain zip) produced by a fixture generator that is **not** included
  in this repo; those checks fail until you supply equivalent files.
- `browser-check.mjs` and `wrapper-check.mjs` drive headless Chromium through
  `playwright-core`, which is not a dependency of the app. Set
  `PLAYWRIGHT_CORE_DIR`, and optionally `CHROMIUM_PATH` and `APP_URL`.

## Repository layout

```
docker-compose.yml           the stack (Traefik labels; needs an external reverse proxy)
.env.example                 hostnames, image pins, and CHANGE_ME secrets
opentdf.yaml                 platform config; secrets come from env, not this file
keycloak_data.example.yaml   realm, roles, clients, demo users for `provision keycloak`
web/                         tdf-lab-web image: Dockerfile, nginx config template, entrypoint
.github/workflows/image.yml  builds, smoke-tests, Trivy-gates and publishes both images
postgres-init/               first-boot script: separate Keycloak role + database
webapp/                      browser console (Vite + React + TypeScript, @opentdf/sdk 0.20.0)
  src/wrapper/               self-decrypting HTML wrapper: page, device grant, build template
  scripts/                   stage 2 of the wrapper build
  e2e/                       verification harnesses (see above)
shareapi/                    ciphertext-only file store (Node, Express 5, jose) + its Dockerfile
dbdemo/                      field-level encrypted SQLite demo (Python stdlib + otdfctl)
docs/                        write-up (WHITEPAPER.md)
```

### What is not in this repo

The lab's working directory also held secrets (`.env`, the filled-in
`keycloak_data.yaml`, the KAS private keys), database backups, generated
artifacts (the built SPA, the generated wrapper runtime, sealed sample
wrappers, `records.json`, `records.sqlite`), local test-fixture generators, and
a long build journal written against the specific deployment. None of those
are published. Source comments still cite the journal by section, as "lab
journal §N" (for example §10l for the wrapper, §10i for the console layout
fixes, §8 for teardown). The journal is not included; the comments stand on
their own, and this README covers the steps needed to run the lab.

## Status

A learning lab, not production software. It was built and exercised by one
person over about a week, with demo accounts, a password-grant client, a
permissive CORS entry for wrappers, a single-node PostgreSQL shared by two
services, and no backup, monitoring, or key-rotation story. Versions are
pinned to what the lab ran in 2026-08 and 2026-09 and will age. Use it to
learn how TDF-style access control behaves, not to protect real data.

License: MIT. See [LICENSE](LICENSE).
