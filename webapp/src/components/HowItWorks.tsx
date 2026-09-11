import { KEYCLOAK_ADMIN_URL, OIDC_AUTHORITY, PLATFORM_URL } from '../config';

const SEQUENCE = [
  {
    label: 'Sign in',
    who: 'browser → Keycloak',
    note: 'Authorization code + PKCE. The realm signs an access token whose audience names the platform. No secret is involved; a public client proves nothing but possession of the code verifier it generated.',
  },
  {
    label: 'Pick attributes',
    who: 'browser → policy service',
    note: 'The console lists namespaces, attributes and values with your own token. These are the labels a payload can be bound to.',
  },
  {
    label: 'Encrypt',
    who: 'browser, then key server',
    note: 'A fresh AES-256-GCM data encryption key encrypts the file in this tab. That key is then encrypted to the key server\'s public key and stored in the manifest as a key access object, with an HMAC binding it to the policy.',
    material: true,
  },
  {
    label: 'Hand over the file',
    who: 'anywhere — including the Library here',
    note: 'The .tdf carries its own policy. It can sit on a USB stick, in someone else\'s inbox, or in this lab\'s shared library, where every signed-in account can list it and download it. The ciphertext is inert without a rewrap, so publishing it is not the same as granting it.',
  },
  {
    label: 'The server holds it and cannot read it',
    who: 'tdf-share-api',
    note: 'The library backend is untrusted by design. The browser seals a file before uploading and opens it after downloading, so the service stores ciphertext and metadata and nothing else — no plaintext, no keys, no passwords. It records the attributes DECLARED in the manifest and rejects anything that is not a well-formed TDF, but it cannot prove those attributes are authentic: it holds no data encryption key, so it cannot check the policy binding. Only a successful rewrap at the key server does that. A listing is a claim; an Open is the proof.',
  },
  {
    label: 'Rewrap request',
    who: 'browser → key server',
    note: 'Decryption starts as a request: here is the wrapped key, here is the policy, here is my token. Nothing is decrypted locally yet.',
  },
  {
    label: 'Authorization decision',
    who: 'key server → policy + entity resolution',
    note: 'The platform resolves your token into a Keycloak account, reads the user attributes off it, and tests them against the subject mappings for every attribute value in the policy. Your entitlements are never carried IN the token — they are looked up here, live, which is why changing an attribute takes effect on the very next request without a new sign-in.',
    decision: true,
  },
  {
    label: 'Allow, or deny',
    who: 'key server → browser',
    note: 'On allow the key comes back rewrapped to an ephemeral key this tab generated, and the payload decrypts here. On deny the rewrap returns HTTP 200 carrying a permission_denied result for the key access object, and the key never leaves the server.',
    decision: true,
  },
];

export function HowItWorks() {
  return (
    <div className="stage__inner">
      <header className="stage__head">
        <p className="eyebrow">Reference — how this works</p>
        <h1 className="stage__title">One file, one decision, every time it is opened</h1>
        <p className="prose">
          Ordinary encryption decides access once, when you hand out the key. A TDF moves that
          decision to the moment of opening: the key is never in the file, only a copy of it
          encrypted to a key server that will be asked, each time, whether you are entitled.
        </p>
      </header>

      <div className="spine" style={{ marginTop: 26 }}>
        {SEQUENCE.map((s) => (
          <div
            className={`node${s.material ? ' node--material' : ''}${s.decision ? ' node--grant' : ''}`}
            key={s.label}
          >
            <div className="node__label">
              <span>{s.label}</span>
              <span className="node__size">{s.who}</span>
            </div>
            <p className="node__note">{s.note}</p>
          </div>
        ))}
      </div>

      <hr className="hr" />

      <p className="eyebrow">This lab</p>
      <div className="kv" style={{ marginTop: 10 }}>
        <span className="kv__k">platform</span>
        <span className="kv__v">{PLATFORM_URL}</span>
        <span className="kv__k">realm</span>
        <span className="kv__v">{OIDC_AUTHORITY}</span>
        <span className="kv__k">users</span>
        <span className="kv__v">
          user-a (classification = secret) · user-b (classification = public)
        </span>
        <span className="kv__k">flip it</span>
        <span className="kv__v">
          <a href={KEYCLOAK_ADMIN_URL} target="_blank" rel="noreferrer">
            Keycloak admin console
          </a>
        </span>
      </div>
      <p className="prose" style={{ marginTop: 16 }}>
        Seal a file as user-a with <em>classification/secret</em>, sign in as user-b, and try to open
        it. Then give user-b that same attribute value in Keycloak and press Decrypt again — no
        sign-out, no new token, no restart of anything. The identical file opens, because the
        entitlement was never in the token to begin with.
      </p>
      <p className="prose" style={{ marginTop: 10 }}>
        In the Library the same experiment takes one click: publish as user-a, sign in as user-b, press
        Open. User B can always press <em>Get .tdf</em> and walk away with the bytes — that is the
        distinction the whole design rests on.
      </p>
      <p className="prose" style={{ marginTop: 10 }}>
        <strong>Wrap as HTML</strong> makes the same point from the other side. Encrypt and the
        Library will both hand you the sealed file as a single self-contained{' '}
        <span className="material">.html</span> page. Opened from your filesystem it reads its own
        manifest with no network at all — the attributes, the key server, the policy uuid, the fact
        that the payload is ciphertext — and then says plainly why it still cannot open itself
        there: a document loaded from a disk has the origin <span className="material">null</span>,
        which no identity provider will issue a token to and no key server will accept a request
        from. Served from this console's own origin the very same file signs in and decrypts in
        place. The file never changed; the origin did. That is the whole thesis in one artefact —
        and it is also why an .html from a stranger deserves the same suspicion as any other
        executable.
      </p>
      <p className="prose" style={{ marginTop: 10 }}>
        <em>classification/public</em> is the counterpart: its subject mapping accepts{' '}
        <em>public</em> or <em>secret</em>, so a secret-holder can read public data and not the
        reverse — a two-level hierarchy built from one attribute and two mappings.
      </p>
    </div>
  );
}
