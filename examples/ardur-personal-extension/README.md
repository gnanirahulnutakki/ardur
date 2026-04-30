# Ardur Personal Extension Prototype

This is a dependency-free Manifest V3 prototype for Ardur Personal Lite.

It is a browser-local observation and consent layer for user-enabled sites. It
does not claim to be a complete enforcement boundary and it does not emit
standard Ardur Execution Receipts. The stronger path is extension plus native
host, where the host owns keys and exports normal Ardur evidence bundles.

## Load Locally

Chrome-compatible browsers:

1. Open `chrome://extensions`.
2. Enable developer mode.
3. Load this directory as an unpacked extension.
4. Open a supported site, click the extension, and enable the current origin.

Firefox temporary install:

1. Open `about:debugging#/runtime/this-firefox`.
2. Load `manifest.json` as a temporary add-on.
3. Enable a site from the popup.

## Runtime Smoke

The tracked smoke runner loads the unpacked extension into Chrome for Testing
or Chromium, opens a local page, injects the content script, and verifies that a
digest-only browser receipt was signed.

```bash
# from the repo root
node examples/ardur-personal-extension/scripts/smoke.mjs
```

Use `HEADLESS=0` for a visible browser. The runner writes temporary profile and
copied-extension files under `.context/extension-smoke/`, which is ignored.

To include the native host boundary:

```bash
WITH_NATIVE_HOST=1 node examples/ardur-personal-extension/scripts/smoke.mjs
```

Native mode installs a temporary host manifest into the isolated browser profile,
forwards the signed browser receipt to the Python host, verifies the host-signed
Ardur receipt, and checks the host JSONL evidence record.

Regular branded Chrome may ignore extension-loading flags in recent releases.
Use Chrome for Testing, Chromium, or set `CHROME_PATH` to a compatible browser.

## What It Does

- Requests host access per origin; it does not request global host access.
- Injects a content script only after the user enables the current site.
- Hashes observed page text and sends normalized digest-only events.
- Optionally captures visible prompt/answer excerpts after the user enables
  visible-text review for that site.
- Builds a readable Session Review with detected action boundaries for Grok,
  Claude, ChatGPT, Codex, Kimi, and generic AI websites.
- Stores a browser-local, hash-chained receipt timeline.
- Signs browser-local receipts with Web Crypto.
- Keeps native messaging optional and off by default.
- Exports local receipts and session reviews as JSON from the popup.
- Forwards the latest signed browser receipt to `dev.ardur.personal` when the
  user enables native messaging. If a Session Review exists for that receipt,
  it is signed and forwarded with the receipt for host-side verification.

## Manual Test Flow

1. Load the unpacked extension in Chrome.
2. Open an AI website such as Grok, Claude, ChatGPT, Codex, Kimi, or another
   chat-style AI site.
3. Click the extension and press **Enable** for that site.
4. Turn on **Capture visible text** if you want a readable Session Review. Leave
   it off for digest-only evidence.
5. Press **Observe** after the AI answer changes.
6. Check **Session Review** in the popup for action boundaries, labels, and the
   latest summary.
7. Press **Export** for JSON evidence.
8. After installing the native host, press **Host** to forward the latest
   receipt and signed Session Review to the local host evidence log.

## Evidence Boundary

`browser_local_receipt` is low-assurance personal evidence. It is useful for a
local timeline and user review, but browser storage is mutable and extension-held
keys are weaker than native-host keys.

The Session Review is based on browser-visible DOM text only. It cannot attest
server-side model reasoning, hidden tool calls, provider logs, or network events
that are not visible to the browser extension.

Use the native-host path before claiming offline-verifiable Ardur evidence.

The native host prototype lives in
[`../ardur-personal-native-host`](../ardur-personal-native-host/).
