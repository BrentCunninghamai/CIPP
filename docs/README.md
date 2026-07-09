# CIPP GitHub Pages — project landing site

This folder is the source for the static **project landing page** published to
GitHub Pages by [`.github/workflows/deploy_github_pages.yml`](../.github/workflows/deploy_github_pages.yml).

> [!IMPORTANT]
> This is an **informational** site only. The CIPP portal itself is self-hosted
> and sits behind Microsoft Entra ID (Azure AD) authentication with its own
> backend API. The authenticated application, tenant data, and credentials are
> **never** served from GitHub Pages. Do not point Pages at the Next.js `out/`
> build — that app is designed to run on Azure Static Web Apps behind auth.

## One-time setup

1. Push this branch and merge to `main`.
2. In the repo, go to **Settings → Pages**.
3. Under **Build and deployment**, set **Source** to **GitHub Actions**.

The workflow then runs on every push to `main` that touches `docs/**` (or can be
triggered manually from the **Actions** tab via **Run workflow**).

## Contents

| File | Purpose |
| --- | --- |
| `index.html` | The landing page (self-contained, no external assets). |
| `404.html` | Custom not-found page. |
| `.well-known/security.txt` | RFC 9116 machine-readable security contact. |
| `robots.txt` / `sitemap.xml` | Crawler guidance. |
| `.nojekyll` | Disables Jekyll so dot-directories (`.well-known`) publish. |
| `assets/` | Favicon and logo (copied from `public/`). |

## Security decisions

GitHub Pages **cannot serve custom HTTP response headers**, so hardening is done
with the mechanisms browsers honour from within the document, plus a deliberately
minimal page:

- **Strict Content-Security-Policy** (`<meta http-equiv>`): `script-src 'none'`
  means no JavaScript runs at all; every other resource is restricted to
  same-origin (`default-src 'none'`). This is the strongest practical mitigation
  against XSS / content injection on a static host.
- **Fully self-contained**: no external scripts, fonts, analytics, or network
  calls — no third-party attack surface and nothing to leak.
- **No referrer leakage**: `<meta name="referrer" content="no-referrer">` and
  `rel="noopener"` on all outbound links.
- **Hardened deploy pipeline**: the workflow starts from `permissions: {}`
  (deny-all) and grants only `contents: read` to build and `pages: write` /
  `id-token: write` to deploy; it audits egress with `harden-runner`, checks out
  with `persist-credentials: false`, and uploads only `./docs`.
- **Dependency monitoring**: `.github/dependabot.yml` already watches the
  `github-actions` ecosystem weekly, so the actions used here stay patched.

### Known limitation — headers Pages can't set

`X-Frame-Options` / CSP `frame-ancestors`, `X-Content-Type-Options: nosniff`,
and `Strict-Transport-Security` (HSTS) can only take effect as **real response
headers**, which GitHub Pages does not allow you to customise. (`frame-ancestors`
is included in the meta CSP for intent, but browsers ignore it from a `<meta>`
tag by spec.) If you need those enforced, front the site with a CDN/proxy that
can inject headers — e.g. Cloudflare — or host on a platform that supports a
`_headers` file (Netlify / Cloudflare Pages). GitHub already serves all
`*.github.io` domains over HTTPS with HSTS at the platform level, and the
default **Enforce HTTPS** Pages setting should stay enabled.
