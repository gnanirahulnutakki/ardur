# Ardur Personal Native Host Prototype

This example is the Full-mode companion for the browser extension prototype.
It is a native messaging host that receives a signed browser-local receipt,
verifies the browser receipt signature, optionally verifies a signed Session
Review from the extension, issues a normal signed Ardur Execution Receipt with a
host-owned key, and appends a local JSONL evidence record.

It is still a local prototype. It does not install itself system-wide and it
does not claim hardware-backed key custody.

## Development Smoke

From the repo root:

```bash
PYTHONPATH=python python3 -m vibap.cli personal-native-host \
  --once-json examples/ardur-personal-native-host/sample-message.json
```

The checked-in sample intentionally is not signed, so it should return an
invalid-signature response. The automated Python tests generate signed browser
receipts and verify the host receipt path.

## Browser Integration Smoke

The extension smoke runner can exercise the native messaging boundary end to
end:

```bash
WITH_NATIVE_HOST=1 node examples/ardur-personal-extension/scripts/smoke.mjs
```

The runner installs a temporary native host manifest into the isolated Chrome
profile under `.context/extension-smoke/`, forwards the signed browser-local
receipt, verifies the host-signed Ardur Execution Receipt, and confirms the
host wrote `receipts.jsonl`.

## Browser Manifest

Chrome-compatible native messaging hosts need a host manifest whose `path`
points to an executable. Use the wrapper in this directory:

```bash
PYTHONPATH=python python3 -m vibap.cli personal-native-manifest \
  --host-path examples/ardur-personal-native-host/ardur-personal-host \
  --extension-id <chrome-extension-id> \
  --browser chrome-for-testing
```

For Chrome for Testing on macOS, place the generated JSON at:

```text
~/Library/Application Support/Google/ChromeForTesting/NativeMessagingHosts/dev.ardur.personal.json
```

For regular Chrome on macOS, use:

```text
~/Library/Application Support/Google/Chrome/NativeMessagingHosts/dev.ardur.personal.json
```

The host stores evidence under:

```text
$ARDUR_PERSONAL_HOST_DIR
```

or, if unset, under the normal Ardur local home.

## Message Boundary

Accepted messages must use:

```text
ardur.personal.host_observation.v0.1
```

The host rejects known raw page-content fields, requires receipt
`raw_content_included=false`, verifies the browser-local receipt signature, and
can verify a signed `ardur.personal.session_review.v0.1` payload. Session
reviews may include explicit-consent visible-text excerpts from the extension;
they are browser-visible summaries, not provider-side execution logs.
