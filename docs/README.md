# CIPP Bastion — Tier 1 CSP Partner Gateway

This folder is the source for **CIPP Bastion**, the access-gated partner gateway
published to GitHub Pages by
[`.github/workflows/deploy_github_pages.yml`](../.github/workflows/deploy_github_pages.yml).

Bastion is a static site with a real cryptographic access gate: partner-only
content ships **as AES-256-GCM ciphertext** (`partner-content.json`) and is
decrypted locally in the visitor's browser with a per-partner access code.
Content for the public is minimal; content for partners is sealed.

> [!IMPORTANT]
> Bastion is a **gateway**, not the portal. The CIPP application is self-hosted
> behind Microsoft Entra ID with its own backend API. Never publish tenant
> data, credentials, or the built Next.js app (`out/`) here.

## How the gate works

```
partner HTML ──seal──▶ partner-content.json         (committed, ciphertext only)
                          │
                          ├─ payload: AES-256-GCM(contentKey, html)
                          └─ slots[]: one per partner (id = random opaque tag)
                               wrapped = AES-256-GCM(KEK_partner, contentKey)
                               KEK_partner = PBKDF2-SHA256(access code, salt, ≥600k)
```

- **One content key, many key slots** (LUKS-style). Each Tier 1 partner gets
  their own access code; each code unwraps the same content key via its own
  slot.
- **Choose your customers**: only organisations you issue a code to can open
  the vault. `seal` fails closed on anything dubious — codes that don't match
  the `gen-code` format (unless you explicitly pass `--allow-custom-codes`),
  metadata-style `_keys`, the public demo code mixed with real partners,
  duplicate ids, and duplicate codes are all rejected.
- **The roster stays private**: partner ids from your codes file are **not**
  published. Each slot gets a random opaque tag; `seal` prints the id → tag
  mapping for your records.
- **Revoke one partner without touching the rest**: reseal without their slot.
  `seal` always generates a **fresh content key**, so an old bundle + a revoked
  code is the only thing a removed partner can still open — the newly published
  content is out of their reach.
- **Fails closed**: GCM authentication means a wrong code doesn't "half work";
  it simply fails, and the browser gate reports it. The bundle is self-checked
  through the *shipped* `gate.js` — against the exact serialized JSON — before
  anything is written to disk.
- The access code is never transmitted — PBKDF2 + AES-GCM run in the browser
  via WebCrypto; there is no server, cookie, or telemetry. The page has no
  `<form>`, so there is no native submission path that could ever serialise a
  code into a URL.

## Operating runbook

All commands run from the repo root with Node ≥ 20.

```bash
# 1. Generate a strong access code per partner (~122 bits, unambiguous base32)
node tools/pages-gate/encrypt.mjs gen-code --count 3

# 2. Create your distribution list OUT of git (codes.local.json is gitignored)
#    { "contoso-msp": "T1CSP-…", "fabrikam-it": "T1CSP-…" }
$EDITOR tools/pages-gate/codes.local.json

# 3. Author partner content (start from the example) and seal it.
#    Prints the partner → slot-tag mapping; keep it with your codes file.
node tools/pages-gate/encrypt.mjs seal \
  --content tools/pages-gate/partner-content.example.html \
  --codes tools/pages-gate/codes.local.json

# 4. Sanity-check a code (reads from stdin — keeps codes out of shell history)
node tools/pages-gate/encrypt.mjs verify

# 5. Commit docs/partner-content.json, merge to main, approve the deploy
```

**Onboard a partner**: add them to `codes.local.json`, reseal, redeploy, send
them their code out-of-band. **Offboard**: remove their entry, reseal (key
rotates automatically), redeploy. **A code that was ever committed — even
briefly — is burned**: rotate it. The guards check trees, not git history.

> [!WARNING]
> The committed bundle is the **demo seal**: it opens with the public demo code
> in `codes.example.json` so the gate is demonstrable out of the box. `seal`
> refuses to mix that code with real partners, and CI refuses to publish any
> multi-slot bundle the demo code can open — but rotate to real codes (steps
> 1–3) before sharing anything sensitive.

## Threat model — read this honestly

| Threat | Mitigation |
| --- | --- |
| Casual visitor / crawler reads partner content | Content is ciphertext; the page carries `noindex`. |
| Attacker brute-forces a code offline (bundle is public) | `gen-code` codes carry ~122 bits + PBKDF2-SHA256 ≥ 600k (enforced by `seal` **and** CI) — computationally infeasible. Weak/non-conforming codes are rejected at seal time; `--allow-custom-codes` still enforces ≥ 16 chars, but prefer `gen-code`. |
| Public example/demo strings become working keys | `seal` rejects `_metadata` keys outright, and rejects the public demo code unless it is the *only* slot (`demo`); CI additionally refuses to publish a production bundle the demo code opens. |
| Partner roster disclosure | Codes-file ids are never published — slots carry random opaque tags. |
| Ex-partner keeps their old code | Reseal rotates the content key; new publishes are unreadable to them. (They may retain copies of content they already saw — cryptography can't undo disclosure. Old bundles in git history remain decryptable by that era's codes.) |
| Partner forwards their code | Codes are per-organisation, so exposure is attributable and individually revocable. Deterrence + rotation, not prevention. |
| XSS / script injection on the page | CSP `script-src 'self'` (no inline script), `default-src 'none'`, vault HTML is maintainer-authored and integrity-protected by GCM; `innerHTML` never executes `<script>`. |
| Access code leaks via URL / history / logs | No `<form>` → no native GET submission; `verify` reads from stdin; codes never leave the browser page. |
| Malicious or accidental bad deploy | Deny-all workflow permissions, SHA-pinned actions, `harden-runner` egress audit on **both** jobs, `persist-credentials: false`, main-branch-only deploys (dispatch included), single-flight concurrency — plus the `github-pages` environment: add required reviewers and every publish needs a human approval. |
| Secrets committed by mistake | `codes.local.json` / `*.local.*` are gitignored; `bastion_guard.yml` scans **every push and PR on every branch** (recursively, all tracked files) and the deploy workflow re-runs the same guard before publishing. |

**What this is not**: GitHub Pages on a public repo cannot do server-side auth —
anyone can fetch the *ciphertext*, and the repo itself (including
`partner-content.json` history) is public. Sealed bundles from old commits
remain decryptable by the codes of that era, so rotation is the lever that
matters. If you need hard server-side enforcement, the upgrade paths are:

1. **GitHub Enterprise Cloud** — [access-controlled Pages](https://docs.github.com/en/enterprise-cloud@latest/pages/getting-started-with-github-pages/changing-the-visibility-of-your-github-pages-site)
   (visitors must be repo members), or
2. **Cloudflare Access / Zero Trust** (or similar) in front of a custom domain —
   real SSO per customer, and it can also inject the response headers Pages
   can't set.

Bastion's client-side sealing composes cleanly with either.

## One-time GitHub setup

1. **Settings → Pages** → Build and deployment → **Source: GitHub Actions**.
2. **Settings → Environments → `github-pages`** → add **Required reviewers**
   (you / release owners) and restrict the environment to the `main` branch,
   so every deploy needs explicit approval. Until this is configured, deploys
   are gated only by the workflow's main-branch checks.
3. Keep **Enforce HTTPS** enabled (default).
4. If you attach a **custom domain** later, change the 404 page's home link
   from `/CIPP/` back to `/` (project sites are served under the repo path;
   custom domains are served at the root).

## Contents

| Path | Purpose |
| --- | --- |
| `index.html` | Public shell + access gate (self-contained, strict CSP). |
| `assets/gate.js` | WebCrypto unlock engine — same file is exercised by the CLI and CI. |
| `partner-content.json` | The sealed vault (ciphertext only — safe to commit). |
| `404.html` | Custom not-found page, same hardening. |
| `.well-known/security.txt` | RFC 9116 security contact. |
| `robots.txt` | Crawler opt-out (see caveat below). |
| `.nojekyll` | Lets dot-directories (`.well-known`) publish. |
| `../tools/pages-gate/` | `encrypt.mjs` (seal/verify/gen-code) + examples. |
| `../.github/workflows/bastion_guard.yml` | Secrets scan on every push/PR. |

### Limitations on project-Pages hosting

- **Response headers**: `frame-ancestors` / `X-Frame-Options`,
  `X-Content-Type-Options: nosniff`, and HSTS only take effect as real response
  headers, which GitHub Pages cannot customise (browsers ignore
  `frame-ancestors` in a meta CSP by spec, so it is deliberately omitted).
  GitHub serves `*.github.io` with platform-level HTTPS; fronting with
  Cloudflare (see above) adds the rest.
- **`robots.txt` / `security.txt` placement**: crawlers and scanners only read
  these from the **origin root** (`https://<owner>.github.io/robots.txt`), not
  from a project path (`/CIPP/robots.txt`), so on a project site they are
  best-effort documentation. The `noindex` meta tag on the page is the control
  that actually works everywhere; both files become fully effective if you
  later attach a custom domain (where the site is served at the root).
