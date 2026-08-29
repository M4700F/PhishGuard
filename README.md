# PhishGuard — Real-Time Phishing Detector

A Chrome extension (Manifest V3) that inspects pages as they load and flags
common phishing patterns:

- **Lookalike / typosquat domains** — `paypal1.com`, `secure-paypal-login.com`, and similar.
- **Suspicious redirect chains** — many domain hops or URL shorteners before the final page.
- **Credential exfiltration** — forms with a password field that submit to a different domain, and JS `fetch`/`XHR` calls that send a password value elsewhere.

## Architecture

The extension is split across four execution contexts, wired together by `manifest.json`:

| File | Runs where | Job |
|---|---|---|
| `manifest.json` | — | Declares permissions and wires every other file together. Chrome reads this first. |
| `background.js` | A **service worker** (no DOM, runs in the background) | The only piece with access to full navigation/redirect history (`chrome.webNavigation`). Sets the toolbar badge and stores results. |
| `content.js` | Injected into every page, **isolated world** | Reads and edits the page's DOM without the page's own JS being able to see or interfere with it. Runs the domain check, scans forms, and renders the warning banner. |
| `inject.js` | Injected into every page, **MAIN world** | Runs as if it were the page's own script — required because hooking `fetch`/`XMLHttpRequest` only works when the patch is applied to the same `window` the page uses. Communicates with `content.js` via `postMessage`. |

The isolated-world-vs-MAIN-world split is the one genuinely non-obvious
concept here: a content script and the page's own `<script>` tags run in the
*same DOM* but *different JS environments*, so neither can see the other's
variables or function overrides. That is why `inject.js` is a separate file
with `"world": "MAIN"` rather than part of `content.js`.

## Installation

1. Open `chrome://extensions`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `phishing-extension` folder.
4. Pin the extension from the puzzle-piece toolbar menu to keep the badge visible.

After editing any file, click the refresh icon on the extension's card in
`chrome://extensions` to load the change.

## Testing

Open `test/fake-login.html` directly in Chrome (drag it into a tab, or use
`file:///path/to/phishing-extension/test/fake-login.html`). It is a fixture
page with a login form whose `action` points at a domain other than the one
serving the page — the exact pattern the extension looks for.

- A red banner should appear at the top of the page.
- Clicking the **PhishGuard** toolbar icon opens a popup listing the flagged issues.
- Clicking **"Log in via JS (fetch)"** also triggers the `inject.js` fetch hook.

The lookalike-domain check requires a real DNS name to visit
(`window.location.hostname` cannot be faked from a local file). It is best
sanity-checked by temporarily adjusting `KNOWN_BRANDS` or the Levenshtein
threshold in `content.js` and adding a `console.log` while browsing normal
sites. Do not visit real phishing pages to test it.

## Known limitations

- **Registrable-domain extraction is naive.** `registrableDomain()` takes the
  last two labels, which is wrong for domains like `example.co.uk` or
  `example.com.bd`. Production use should swap in a Public Suffix List library
  (e.g. `psl` on npm).
- **`KNOWN_BRANDS` is a hardcoded array.** A production version would pull from
  a maintained brand/threat-intel list, or replace the fixed list with a model.
- **Redirect-chain heuristics are simple thresholds** (≥3 unique domains, or
  any known shortener). Phishing kits often use exactly one clean redirect, so
  this catches obvious cases, not sophisticated ones.
- **The fetch/XHR hook only catches plaintext password values.** A page that
  hashes or encodes the password client-side before sending it is not caught
  by the current `bodyContainsPassword()` check.
- **`document_idle` timing** for `content.js` means very fast auto-submitting
  forms could fire before the check runs. `inject.js` runs at `document_start`
  to close this gap for the fetch/XHR path.

## Possible next steps

- Add a real typosquatting/brand list from open threat-intel feeds.
- Replace the fixed edit-distance threshold with a small classifier trained on
  known phishing vs. legitimate URLs; URL structure and lexical features are a
  well-studied ML problem.
- Add an options page for domain whitelisting and sensitivity adjustment.
- Persist a short history of flagged pages (currently cleared on navigation).
- Package proper icons and publish to the Chrome Web Store (requires a
  developer account and a review pass).
