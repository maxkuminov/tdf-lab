# Possession Is Not Access: A Hands-On Study of Mediated Access and Cryptographic Wrapping with OpenTDF

Max Kuminov, CISSP

September 2026

## Abstract

There are two broad ways to control who reads a piece of data. Mediated access puts a policy decision in front of every read: the data stays behind a service, and the service decides. Cryptographic wrapping encrypts the data object itself and binds a policy to it, so the object can travel anywhere and a key access service decides who gets the key. Between 27 August and 1 September 2026 I built a single-host homelab on the open-source OpenTDF platform to see how the second model behaves in practice and where it still depends on the first. The lab covers the command-line ALLOW/DENY loop, a browser console with PKCE sign-in, a shared file library where everyone can download everything, self-contained HTML-wrapped files, and a field-level encrypted SQLite table. This paper reports what was measured: entitlement changes took effect on the next open within about a second with no new token; unentitled users downloaded byte-identical ciphertext and could not read it; an HTML-wrapped file opened from disk exposed its policy metadata with zero network calls; and per-field wrapping cost 58 to 215 times the plaintext size, one key-server call per cell. The conclusion is a set of boundary conditions for choosing between the models, not a winner.

## 1. The problem

### Two models

Most access control in production systems is mediated. A request for data arrives at a service, the service checks who is asking, a policy decision point evaluates the request, and an enforcement point either returns the bytes or does not. NIST SP 800-207 describes zero trust architecture in exactly these terms: a policy engine and policy administrator make and communicate decisions, and a policy enforcement point sits in the data path and carries them out. The data never leaves the protected side unless the decision says so.

Cryptographic wrapping takes a different position. The data object is encrypted with a data encryption key (DEK). The DEK is itself wrapped (encrypted) with a key held by a key access service (KAS). The object carries three things with it: the encrypted payload, a policy describing who may read it (for example, a set of attribute values), and key access information saying which KAS holds the wrapping key and how the policy is cryptographically bound to the wrapped key. The object can then sit on any storage, cross any network, and pass through any intermediary. To read it, a client presents the key access information and its own credentials to the KAS, which checks the policy against the requester's attributes and either releases the DEK (rewrapped to a key the client supplies) or refuses.

The Trusted Data Format (TDF) is an open specification for the second model, and OpenTDF is its reference implementation. OpenTDF uses the name ZTDF for the current revision of the format. A `.tdf` file is a ZIP archive with two members: `0.manifest.json`, which holds the policy, key access objects and integrity information, and `0.payload`, which holds the AES-GCM ciphertext.

### Hypothesis

The two models fail differently, and the difference shows up at the points where a design gets hard: the network edge, disconnected operation, a data copy leaving the system, a revoked user, a compromised storage tier. It is easy to read wrapping as the model that removes the need for a trusted path. My starting hypothesis was that wrapping moves the mediator from the data path to the key path rather than removing it. I wanted to see that with my own hands, with real numbers, rather than argue it from diagrams.

The attribute-based access control (ABAC) terms in this paper follow NIST SP 800-162: subjects have attributes, objects have attributes, and a policy relates the two. In OpenTDF the object attributes live in the TDF's policy, and the subject attributes are resolved from the identity provider at decision time.

## 2. Lab design

### Components

The lab runs on one Docker host, on a dedicated container network with no egress: nothing on it can reach the internet, the LAN, or the host. Ingress arrives only through a TLS-terminating reverse proxy attached to that network. All hostnames in this paper are genericized; the console is `tdf.lab.example`, and the other services use names under `lab.example`.

| Component | What it is | Role in the lab |
|---|---|---|
| OpenTDF platform v0.25.1 | One Go service bundling policy, authorization, entity resolution and the KAS, backed by PostgreSQL 15 | Policy decision point for key release, and the KAS |
| Keycloak 26.x | OpenID Connect identity provider | Issues tokens; holds user attributes the platform reads at decision time |
| `otdfctl` v0.37.0 | OpenTDF command-line client | Admin (attributes, subject mappings) and the CLI encrypt/decrypt loop |
| Web console | React single-page app using `@opentdf/sdk` 0.20.0, public OIDC client `web-console` with authorization code plus PKCE (S256 required) | Encrypt, decrypt, inspect manifests, visualize the protocol |
| Share API and library | Small Node service (Express 5, `jose`) behind a same-origin proxy | Stores and lists ciphertext; never sees plaintext or keys |
| HTML wrapper | A generator that emits one self-contained `.html` page per sealed file | Tests what a portable, self-describing document can and cannot do |
| Field-level demo | A stdlib-only Python script and a SQLite file | Tests wrapping at the granularity of a single database cell |

The policy is deliberately small. One namespace, one attribute (`classification`, rule ANY_OF) with two values, `secret` and `public`. Two subject mappings connect a user attribute in the identity provider to those values: `secret` is satisfied when the user's `classification` is `secret`, and `public` is satisfied when it is `public` or `secret`. That second mapping turns one attribute into a two-level hierarchy. Two demo accounts exercise it: `user-a`, entitled to `secret`, and `user-b`, entitled to `public` only. "Secret" and "public" here are just demo attribute values; they are not tied to any real classification scheme.

KAS keys are an RSA-2048 pair and an EC pair in a static on-disk keyring. There is no HSM and no KAS key management service in this build.

### Read path

The architecture reduces to this sequence:

1. The client signs in to the identity provider and receives an access token. The token must carry the platform's audience, or the platform rejects it before looking at policy.
2. To encrypt, the client fetches the KAS public key, generates a DEK, encrypts the payload with AES-GCM, wraps the DEK to the KAS key, computes a policy binding (an HMAC over the policy, keyed with the DEK), and writes the `.tdf`.
3. To decrypt, the client sends a rewrap request to the KAS: the key access object, the policy, its token, and a public key of its own. The KAS checks the policy binding, asks the authorization service whether this entity satisfies the policy's attributes, and on success returns the DEK wrapped to the client's key. The client then decrypts the payload locally.

The share API is the untrusted half of the lab on purpose. The browser seals a file before upload and opens it after download, so the service holds only ciphertext and metadata and takes no part in the rewrap. It records the attributes declared in the uploaded manifest rather than a client-supplied field, rejects anything that is not structurally a TDF, and verifies every bearer token from scratch against the identity provider's published keys.

### Phases

| Phase | Date | What was built |
|---|---|---|
| 1 | 2026-08-27 | Platform, identity provider and database on the isolated network; policy seeded; CLI ALLOW/DENY/flip loop |
| 2 | 2026-08-27 | Browser console with PKCE sign-in, encrypt, decrypt, manifest inspector, read-only policy explorer |
| 3 | 2026-08-28 | Shared library backed by the share API; everyone can list and download every file |
| 4 | 2026-08-28 | Live protocol sequence diagram in the console, with labels saying which component really performed each step |
| 5 | 2026-08-28 | Self-contained HTML-wrapped TDFs and a handover protocol from a local file to the console |
| 6 | 2026-08-28 | Design evaluation of a self-authenticating wrapper (OAuth device grant, origin `null`) |
| 7 | 2026-09-01 | Field-level encrypted SQLite table, CLI and browser views |

### Review process

Every phase went through at least one reviewer that did not write the thing it checked. Before the first bring-up, the design and compose files went through five rounds with an independent reviewer from a second AI model family (FAIL, FAIL, FAIL, FAIL, PASS). Round one found a real BLOCKER: a Docker network marked `internal` removes off-host routing but still gives the host an address on the bridge, and a test container on such a network reached an SSH service on the host. The fix was to create the network with the bridge driver's isolated gateway mode, which allocates no gateway at all. After the fix the host held zero addresses in the subnet and containers had no default route. The lab would have kept working with the hole in place, so nothing else would have caught it.

The first bring-up was then executed by a separate agent following the runbook cold. It came up clean on the first attempt and surfaced seven runbook defects, including a wrong KAS public-key endpoint and a user-update API call that silently wiped fields. Later phases had non-author browser passes in headless Chromium and a second-family security review of the console and share API.

## 3. Measurements and observations

### ALLOW/DENY loop

The first exit criterion was simple: encrypt a file as `user-a` to the `secret` value, decrypt as `user-a` (ALLOW), decrypt as `user-b` (DENY), then change `user-b`'s attribute and decrypt again. All three behaved as expected on the first run, with no restarts, and the platform's audit log recorded the decision changing from `entitled:false` to `entitled:true`.

The more useful result came from a mistake in my own runbook. It told the reader to mint a fresh token after flipping `user-b`, on the assumption that entitlements were baked into the token at login. I measured it and that was wrong. The access token carries no `classification` claim at all; the entity resolution service reads the attribute from the identity provider at the moment of each decision. With one already-issued token:

```
t+0s   attribute=public            decrypt -> permission_denied
t+1s   attribute set to secret
t+2s   same token                  decrypt -> plaintext
t+7s   same token                  decrypt -> plaintext
t+12s  same token                  decrypt -> plaintext
t+14s  attribute set back to public
t+16s  same token                  decrypt -> permission_denied
```

The decision followed the attribute within about a second in both directions, with no re-login, no refresh, and no caching I could observe. This is the property wrapping advertises (decide at open time against live state), and my own documentation had been denying it.

Two details of the denial are worth knowing if you build on this platform. First, a rewrap denial on platform v0.25.1 is an HTTP 200 whose per-key-access result carries an error, not an HTTP 403. The browser SDK turns that into an exception with a fixed message and drops the platform's own text, so an interceptor watching only for failed HTTP calls records the denial as a success. The console had to read the response body to show the real reason. Second, a denial and a tampered policy are different answers. Editing the policy inside a `.tdf` breaks the policy binding, and the KAS answers `invalid_argument` with `[tamper detected]` in its message. I could reproduce that by swapping `/secret` for `/public` in the base64 policy, which keeps the length identical so no ZIP offset moves. The console ended up reporting four distinct outcomes: access denied, policy binding mismatch, payload integrity failure (rewrap succeeded, AES-GCM tag failed), and token rejected.

One policy lesson came from this loop too. As first seeded, the `public` value had no subject mapping at all. `user-b` sealed a file to `public` and was then refused his own file. Nothing warned about it; an unsatisfiable attribute value just looks like a denial.

### The shared library

The shared library made the thesis visible. Every signed-in account can list every file and download the sealed bytes of any of them. The harness confirmed that `user-b` downloads a `user-a` file byte-identical to what was uploaded and is refused on decrypt, while `user-a` opens a file `user-b` published to `public`. In the field-level demo's browser view, the sealed table is served as a static JSON file with no authentication at all, and a non-author check confirmed that an unauthenticated `curl` retrieves it. That is intentional. The ciphertext is inert; reading it still costs a rewrap, and the KAS answers per file, per account, every time.

Building the library exposed a trust question I had not thought through. The share API holds no DEK, so it cannot check the policy binding HMAC. It can confirm that an upload is a well-formed TDF, but it cannot prove the attributes declared in the manifest are the ones the key was actually bound to. An authenticated uploader could publish a structurally valid file whose manifest claims `public` while the key is bound to something else. The listing would be wrong; access would not change, because the file would simply fail to open for the wrong people. The phrase I settled on for the UI was "a listing is a claim; an Open is the proof."

A related limit: standard users cannot ask the platform what they are entitled to. The entitlements call is refused to them (both demo users got `permission_denied`), and entitlements are not in the token. So the browser cannot predict whether a file will open. The library can only remember what the KAS decided for files already opened, and even that generalizes poorly: an ANY_OF grant on a file bound to {A, B} proves only that at least one of A or B passed, so it says nothing about a file bound to {A} alone.

### HTML wrapper and origins

Phase 5 asked what happens when a sealed file is packaged as a single HTML page you can email or copy to a USB stick. The page contains the ciphertext, the manifest and a small reader.

I checked the SDK before building a generator, and the checking mattered. `@opentdf/sdk` 0.20.0 keeps an HTML reader (`unwrapHtml()`, which pulls base64 out of a specific input element) but has removed every writer: the HTML format setters throw a configuration error, the format check is hardcoded to false, and the legacy `asHtml` encrypt option throws. The reader is also wired only into the legacy client, not the `OpenTDF` class the console uses. So I generated the page myself in the same shape and proved compatibility by round-tripping a generated page through the SDK's own `unwrapHtml()`.

The same file behaved differently depending on where it was opened:

| Opened from | Behaviour |
|---|---|
| `file://`, a USB stick, an email attachment, any other host | Reads its own manifest with zero network requests and shows the attribute FQNs, KAS URL, policy UUID, schema version and size; explains that it cannot decrypt here |
| The console's own origin | Signs in with PKCE, performs a real rewrap, decrypts in the page; `user-a` sees plaintext, `user-b` on a `secret` file gets `permission_denied` |

Nothing about the file changed between those two rows; only the origin did. A browser loading a document from the filesystem gives it an opaque origin, which serializes as `null`. No OAuth client can register a redirect URI back to a `null`-origin document, and adding `null` to a CORS allowlist admits every filesystem document and every sandboxed frame, not this one file. So the portable page could read everything it needed except the key.

Injection safety was designed to be structural rather than a matter of careful escaping. A `.tdf` someone hands you is attacker-controlled, including its filename, attribute FQNs, dissemination list and MIME type. The page template has exactly two substitution slots, both inside double-quoted attributes, and both are validated against a strict base64 pattern; the generator throws rather than emit anything else. Base64 contains no `<`, `"`, `'` or `&`. Everything the page displays is read out of the embedded TDF at runtime by its own ZIP64-aware reader and written with `textContent`. A fixture whose attribute FQN ended in `"><script>window.__pwned=1</script>` rendered as visible text, the flag stayed undefined, the live DOM contained exactly one script element, and no injected image or SVG elements appeared.

Because nothing variable ever reaches markup, the inline script is byte-identical in every page generated, so its SHA-256 is a stable Content Security Policy hash. The path that serves wrappers pins `script-src` to that one hash. That makes a failure of the escaping rule non-exploitable on the console's origin: an injected script would not match the hash and would not run, so it could not reach the session storage where the token lives. The CSP is defence in depth; the primary control is that hostile strings never reach markup.

TDF archives also need a careful reader. The SDK's ZIP writer always emits ZIP64 with `0xffffffff` size sentinels in every local file header, at any file size; the real sizes live in the central directory's ZIP64 extra field. A reader that trusts local headers sees a valid `.tdf` as two empty entries.

### Handover protocol

The portable page could not decrypt, so it needed a way to hand its bytes to the console without ever holding a credential. The design:

1. The page opens the console at a handoff URL with a 128-bit random nonce in the URL fragment, so the nonce never reaches the server.
2. It posts `{hello, nonce}` to the console's window with an explicit target origin, transferring one end of a `MessageChannel`.
3. The console accepts only if it is in handoff mode, the message came from `window.opener`, the nonce matches its own fragment (exactly 32 hex characters, consumed on first use), the sender's origin is `null` or the console's own, and a port was transferred.
4. The console replies `ready` on the port, and only then does the page transfer the payload as an `ArrayBuffer`.

The port is the reason this works without a wildcard. A `file://` document's origin is `null`, and nothing can address a `postMessage` to it except `'*'`. A transferred port is a capability instead of an address, so no wildcard target origin appears anywhere in the feature. What the protocol establishes is narrow: the bytes came from the window that opened the console, and a wrapper rehosted on a third-party site is refused. What it does not establish is that the local document is authentic; nothing can authenticate a `null`-origin document, which is why it had to hand over at all. That is acceptable because the console treats the payload as wholly untrusted ciphertext, and nothing flows back to the page except `ready` and an acknowledgement.

The wrapper also deliberately did not carry its own decrypt code in this design. A wrapper is an attacker-supplied document. If it shipped its own OIDC client and rewrap implementation, anyone who could hand you an `.html` could hand you the code that touches your access token.

### Self-authenticating variant

The obvious question was why a wrapper cannot just sign in and decrypt in place. The obstacle is not cryptography: in Chromium, `file://` counts as a potentially trustworthy scheme under the Secure Contexts specification, so the page is a secure context with full WebCrypto. I measured `isSecureContext: true`, RSA-OAEP key generation (a 294-byte SPKI), ECDSA P-256 signing and AES-GCM encryption all working from a `file://` page. The obstacle is authentication, because browser OAuth flows redirect. The OAuth 2.0 Device Authorization Grant (RFC 8628) never redirects: the page shows a short code, the user types it into the identity provider's own page in a normal tab, and the page polls the token endpoint until a token is issued.

A design that uses the device grant this way has to accept two costs, and I think both should be printed on the page for the reader:

1. The KAS and the identity provider must allow `Origin: null` in CORS. That does not admit "this file"; it admits every filesystem document and every sandboxed frame. A valid token is still required and no policy decision changes, so nothing becomes readable that was not readable before, but the set of pages allowed to ask gets much larger.
2. The wrapper's own JavaScript now handles the user's access token and the plaintext. In the console that code is served by the origin that owns the credentials. In a wrapper it arrived in the same file as the ciphertext, from whoever sent it. Opening a wrapper becomes choosing to run the sender's program. I believe this is why commercial products in this space send a link to a web application rather than a self-decrypting document.

What the variant cannot do is support an arbitrary foreign HTTPS origin. The platform sends credentials in CORS, and the Fetch standard forbids `Access-Control-Allow-Origin: *` together with credentials, so there is no "any origin" value to configure. Supporting foreign hosts would mean turning credentialed CORS off, which is a much larger widening than adding `null`.

The variant was only partly verified. Its pieces were measured and its generator harness passed, but the full chain from approval to plaintext was never run end to end by automation, because automating the device approval meant scripting a password entry that the tooling declined to do. I treat it as a design evaluation, not a verified feature.

### Field-level encryption

Phase 7 applied wrapping at the smallest granularity I could think of: a single database cell. A SQLite `employees` table keeps name, department and `classification` in plain columns, which stay queryable. The three sensitive columns (`ssn`, `salary`, `notes`) exist only as ZTDF ciphertexts, one TDF per cell, each sealed under the row's `classification` value. Five fictional rows, three protected fields, fifteen sealed cells.

Results, run for real on 2026-09-01:

- `user-a` decrypted 15 of 15 cells.
- `user-b` decrypted the 6 cells in `public` rows and was refused by the KAS on all 9 cells in `secret` rows. The refusal comes from the key server; there is no client-side check.
- `strings` over the database file found zero plaintext of any sensitive value.
- Each cell costs one KAS rewrap to read, so rendering the full table as `user-a` is fifteen key-server calls.

The size cost is the part to budget for. Measured from the demo database, each sealed cell is 1,723 to 1,746 bytes, protecting 8 to 30 bytes of plaintext. Per cell that is 58 to 215 times the plaintext; across the table, 232 bytes of plaintext became 25,967 bytes of ciphertext, about 112 times. Almost all of that is the ZIP container and the self-describing JSON manifest, which is the same size whether the payload is an eight-byte salary or a paragraph.

This demo was originally scoped for NanoTDF, the compact binary TDF variant designed for this kind of workload, which the lab record estimated at about 300 bytes per cell. NanoTDF no longer exists in OpenTDF. It was removed in one sweep in the v0.12.0 releases of 27 January 2026 (platform PR #3013, "fix!: remove nanotdf support"): the KAS nano rewrap path, the Go SDK's create and read functions, `otdfctl`'s nano option, the supporting crypto helpers, and the NanoTDF documentation in the spec repository. The stated rationale was consolidation on the standard format to reduce the burden of maintaining two wire formats, not a vulnerability. The last nano-capable service and SDK release was v0.11.0, from October 2025. Against a v0.25.1 KAS, no client of any age can complete a NanoTDF round trip: an old SDK could still create a nano ciphertext, but nothing could rewrap it. For compact per-field encryption on this platform, that leaves standard TDF with its manifest overhead, or a different design (for example, wrapping one DEK per row or per column group and encrypting fields under it), which trades per-cell policy granularity for size.

### Instrumentation honesty

Two findings from the review passes are not about TDF at all, but they changed how I trust the lab's own output. The console kept a session-long log of RPC calls, and its error classifier explained a failure by searching that log for the most recent rewrap failure. Decrypt a denied file, then decrypt a file whose rewrap succeeds but whose payload fails its integrity tag, and the second failure was explained with the first one's denial: the UI reported "access denied, the file is intact" about a file that was not intact. The log was correct; the query had no time bound. Every lookup now takes a cursor captured at the start of the operation. The second was in the protocol diagram, which first labelled the KAS's refusal as "never reached" when on a denial the answer is in fact delivered, inside an HTTP 200. A teaching tool that misreports which component made a decision teaches the wrong model.

## 4. Failure modes

### Mediated access

Mediated access is strong exactly where the enforcement point is. Every read is a decision, the decision can use live state, and the audit trail is a side effect of serving the data. It breaks in three places.

At the network edge. The enforcement point has to be reachable and has to be in the path. The lab produced a small, concrete version of this: the reverse proxy's shared security-header middleware was configured with CORS options, and a proxy configured that way answers CORS preflight requests itself. The preflight never reached the platform, and the canned reply carried no `Access-Control-Allow-Origin`. Every browser call to the platform failed while `curl` worked perfectly. An intermediary between the client and the real decision point had silently become its own, wrong, decision point.

In disconnected operation. If the data lives behind the service, a client with no path to the service has no data.

Once bytes leave the enforcement point. After the service returns plaintext, the service has no further say. A copy in an email, an export, a backup or a partner's system carries no policy with it. Any policy on that copy has to be re-established by whoever holds it.

### Cryptographic wrapping

Wrapping fixes the third problem for the ciphertext: the policy travels with the object, and the lab showed that holding the object gives you nothing. The share API, an unauthenticated static file, a USB stick and an email attachment were all equivalent storage. But the lab also showed where the problem moved.

Key release is still mediated. Every read in this lab required the KAS to be online and reachable, and every read was a live policy decision by the platform. That is mediated access, applied to keys instead of data. Wrapping changes what the enforcement point protects and how much of the system has to be trusted (the share API could be fully untrusted), but it does not remove the need for an online decision at read time. The disconnected case is not solved; it becomes the question of whether a KAS is reachable. I did not test any offline or cached key release mode, and nothing in this lab supported one.

Revocation is as good as the next rewrap. The flip trace showed that changing an attribute changed the next decision within about a second, with no token change. That is good revocation for future opens. It does nothing for plaintext already released, for a client that keeps a DEK after decrypting, or for a deployment that caches decisions or keys closer to the client. The lab had no caching I could observe; a production deployment that adds caching for latency or availability trades revocation speed for it.

Metadata leaks by design. The manifest has to be readable before decryption, because the client needs it to find the KAS and the KAS needs the policy to decide. The `file://` wrapper showed what that means: with zero network calls and no credentials, a page read the attribute FQNs, the KAS URL, the policy UUID, the schema version and the size of the protected object. The policy in a TDF manifest is base64, not encrypted. Anyone who holds the file learns which attributes protect it and which key service governs it. Attribute names chosen for administrators ("classification/secret", a project name, a customer name) become information disclosed to every holder. This is the finding I would put first in a design review: in a wrapping system, attribute naming is a data classification decision in its own right.

Key management becomes the whole problem. In the lab the KAS keys were a static on-disk keyring. Whoever holds those private keys can unwrap every DEK in every file ever sealed to them, without asking any policy engine. Wrapping concentrates risk in the KAS key material and in the KAS software itself; HSM-backed keys, key rotation and split-key schemes (multiple KASes that must each approve) exist to manage exactly that, and none were exercised here.

Size and call volume scale with granularity. At file granularity a fixed overhead of about 1.7 KB matters little. Per-cell wrapping cost 58 to 215 times the plaintext and one KAS call per cell read. The compact format that was designed for fine-grained use has been removed from the reference implementation. Protected fields also stop being queryable: you cannot filter, index, join or aggregate on a column the database cannot read.

Portable documents hit the browser's origin model. A wrapped document either hands its bytes to a trusted origin, or accepts a much larger CORS surface and runs the sender's code with the user's token. On the server side, a service without the DEK cannot verify a manifest's policy binding, so any index built from manifests is a claim rather than a fact.

### Boundary conditions

I don't think either model wins in general. These are the conditions I would use to choose.

Prefer mediated access when:

- the data does not need to leave a service you control, and consumers can always reach that service;
- the protected fields must stay queryable, indexable or aggregatable by the storing system;
- records are small and numerous, and per-record overhead or per-read key calls would dominate cost;
- the identity of every reader and every read must be logged by the system that holds the data.

Prefer cryptographic wrapping when:

- the object has to cross storage, transport or organizations you do not trust, or has to be held by intermediaries that must not read it (the share API case);
- the same policy has to be enforced consistently across several systems that do not share an enforcement point;
- revoking future access to copies already distributed matters, and "the next open is refused" is an acceptable definition of revocation;
- a KAS can be kept highly available to every legitimate reader, and its key material can be protected to a standard at least as high as the data.

Neither model covers:

- plaintext after release (both models end at the point of decryption);
- truly disconnected reading, unless you add an offline key release scheme with its own revocation limits;
- confidentiality of policy metadata, in the wrapping case, unless attribute names are chosen with that in mind.

Several of the lab's surfaces combined the two. The library listing was mediated (authenticated, per-user quotas) while the content was wrapped. That combination is probably the common case in practice: mediate the metadata and the listing, wrap the content, and accept that the KAS is the enforcement point that still has to be online.

## 5. Limitations

- Single host, single operator. Every component ran on one Docker host in a homelab, on personal time. Nothing here measures behaviour under real network partitions, multiple regions or real load.
- Synthetic data. All files, the two users and the five database rows are fictional. `secret` and `public` are demo attribute values only.
- One version of each component. Platform v0.25.1, `@opentdf/sdk` 0.20.0, `otdfctl` v0.37.0, Keycloak 26.x (26.4.7, upgraded to 26.7.2 mid-lab), Chromium for all browser measurements. The NanoTDF removal is a reminder that the format and the SDK surface change; findings about what the SDK does or does not support are specific to these versions.
- No performance benchmarking. The only quantitative results are sizes, counts and the flip timing at one-second resolution. I did not measure rewrap latency, throughput, or KAS capacity.
- No adversarial red team. Security testing was hostile fixtures (injection, forged ZIP sizes, path traversal, wrong token types, expired tokens), policy tamper, and review passes. No one attacked the platform, the identity provider or the KAS directly.
- No HSM or key management service. KAS keys were a static on-disk keyring. Post-quantum KAS key types in the upstream example configuration were omitted. No multi-KAS key splitting.
- Verification by tooling, not people. Checks were the author's own harnesses plus non-author automated passes (a second AI model family for design and security review, separate agents for bring-up and browser checks). These caught real defects, but they are not an independent human audit.
- One unverified chain. The self-authenticating wrapper variant was verified in pieces, not end to end.
- Revocation was measured only for the attribute-flip case with no caching layer present. I did not test token revocation at the identity provider, KAS key rotation, or policy changes on already-distributed files beyond attribute flips.

## 6. How to reproduce

The kit accompanying this paper contains a sanitized copy of the lab with all hostnames genericized (`tdf.lab.example` for the console and names under `lab.example` for the other services), no secrets, and an example environment file. Its layout:

| Path | Contents |
|---|---|
| `README.md` | The runbook: network creation, bring-up, verification gate, policy seeding, the ALLOW/DENY loop, teardown, and the traps listed below |
| `docker-compose.yml`, `.env.example` | PostgreSQL, Keycloak, the OpenTDF platform, a one-shot identity provider provisioning job, the console's static web server and the share API |
| `webapp/` | The browser console, the HTML wrapper generator and the headless and browser check harnesses |
| `shareapi/` | The share API |
| `dbdemo/` | The field-level encryption script |

At a high level:

1. Create an isolated container network first. If your Docker version supports it, use the bridge driver's isolated gateway mode rather than relying on an `internal` flag alone, and confirm the host holds no address on it.
2. Copy `.env.example` to `.env`, generate your own secrets and KAS keys, and bring up the database, identity provider and platform. Run the provisioning job, which creates the `lab-realm` identity domain, the `cli` and `platform` clients, and the two demo users.
3. Run the runbook's verification gate before using the platform. Provisioning is create-only: it never updates an existing client or user and still exits 0, so a changed secret after first boot needs a destructive rebuild.
4. With `otdfctl`, register the KAS, create the namespace, the `classification` attribute and its two values, and the two subject mappings. Give `user-a` the `secret` attribute and `user-b` the `public` attribute.
5. Run the ALLOW/DENY loop, then flip `user-b`'s attribute and retry with the same token. When updating a user through the identity provider's admin API, send the full user representation; a partial update silently clears other fields and returns success.
6. Build the console in a container, create the public `web-console` client (authorization code, PKCE S256 required, exact redirect URI, and an audience mapper for the platform), and add the console origin to the platform's CORS allowlist.
7. Start the share API and try the library as both users. Generate a wrapper and open it from disk and from the console origin.
8. In `dbdemo/`, run `seed`, `view user-a`, `view user-b` and `sizes`.

The runbook's traps section is worth reading first. The two that cost the most time: `docker compose up -d` does not reload an edited bind-mounted configuration file, and nginx `add_header` directives in a `location` block discard those inherited from `server`, which can silently drop a CSP.

## 7. References

1. Rose, S., Borchert, O., Mitchell, S., Connelly, S. *Zero Trust Architecture.* NIST Special Publication 800-207, August 2020. https://doi.org/10.6028/NIST.SP.800-207
2. Hu, V. C., et al. *Guide to Attribute Based Access Control (ABAC) Definition and Considerations.* NIST Special Publication 800-162, January 2014. https://doi.org/10.6028/NIST.SP.800-162
3. OpenTDF project documentation. https://opentdf.io
4. OpenTDF platform repository (platform service, SDKs, `otdfctl`). https://github.com/opentdf/platform
5. OpenTDF specification repository. https://github.com/opentdf/spec
6. OpenTDF platform pull request #3013, "fix!: remove nanotdf support," January 2026. https://github.com/opentdf/platform/pull/3013
7. OpenTDF platform releases. https://github.com/opentdf/platform/releases
8. Keycloak documentation. https://www.keycloak.org/documentation
9. Sakimura, N., Bradley, J., Agarwal, N. *Proof Key for Code Exchange by OAuth Public Clients.* RFC 7636, September 2015. https://www.rfc-editor.org/rfc/rfc7636
10. Denniss, W., Bradley, J., Jones, M., Tschofenig, H. *OAuth 2.0 Device Authorization Grant.* RFC 8628, August 2019. https://www.rfc-editor.org/rfc/rfc8628
11. Lodderstedt, T., et al. *Best Current Practice for OAuth 2.0 Security.* RFC 9700, January 2025. https://www.rfc-editor.org/rfc/rfc9700
12. WHATWG. *HTML Living Standard*, sections on origins (including opaque origins) and channel messaging (`MessageChannel`). https://html.spec.whatwg.org/
13. WHATWG. *Fetch Standard*, CORS protocol. https://fetch.spec.whatwg.org/
14. W3C. *Secure Contexts.* https://www.w3.org/TR/secure-contexts/
15. W3C. *Content Security Policy Level 3.* https://www.w3.org/TR/CSP3/
