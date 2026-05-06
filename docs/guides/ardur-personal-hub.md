# Ardur Personal Hub

Ardur Personal Hub is the regular-user local product shape for Ardur on Mac.
The Hub runs the real Python Ardur runtime locally and receives events from thin
browser, desktop, and CLI adapters.

## Install Shape

Developer install:

```bash
cd python
pip install -e .
ardur setup
ardur hub
```

Target Homebrew install:

```bash
brew install gnanirahulnutakki/ardur/ardur-personal
ardur setup
brew services start ardur-personal
```

## Use

Browser:

1. Start the Hub.
2. Load `examples/ardur-personal-extension` as an unpacked extension.
3. Enable the current AI site.
4. Optional: enable visible-text capture for readable excerpts.
5. Review evidence in the popup or at `http://127.0.0.1:8765/dashboard`.

CLI:

```bash
ardur run -- codex
ardur run -- claude
ardur run -- python script.py
```

Desktop:

```bash
ardur desktop-observe
```

## Evidence Levels

- `enforced`: Ardur controlled the local action boundary, such as `ardur run`.
- `attested`: Ardur signed an observation or receipt.
- `observed`: The local adapter saw browser, desktop, or CLI state.
- `blocked`: Hub policy denied a controllable action.
- `insufficient_evidence`: The provider-side activity was not locally visible.

## Boundary

The Hub can enforce CLI commands and adapter-mediated checks. It cannot control
hidden server-side behavior inside Claude, ChatGPT, Grok, Codex web, Kimi, or
other third-party services unless those providers expose a tool/action boundary
that Ardur owns.
