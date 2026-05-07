# `ardur` CLI Reference

The `ardur` console entry point ships with the Python package. After
`pip install -e python/`, run `ardur --help` to see this list at runtime.

The CLI splits into two groups:

- **Protocol path** — `start`, `issue`, `verify`, `attest`. Used by builders
  who want to issue Mission Passports and run a governance proxy directly.
- **Personal path** — `hub`, `setup`, `status`, `doctor`, `doctor-claude-code`,
  `uninstall`, `run`, `desktop-observe`, `personal-native-host`,
  `personal-native-manifest`, `profile init`, `protect claude-code`,
  `cc-hook`, `cc-report`. Used by the local Ardur Personal product shape.

Source: [`python/vibap/cli.py`](../../python/vibap/cli.py).

## Protocol Path

### `ardur start`

Start the local governance proxy HTTP service. Optionally issue a Mission
Passport from a JSON mission file and start a session immediately.

```text
ardur start [--host HOST] [--port PORT] [--mission FILE]
            [--keys-dir DIR] [--state-dir DIR] [--log-path FILE]
            [--require-auth | --no-require-auth]
```

Defaults: bind `127.0.0.1:8080`. Auth required by default.

### `ardur issue`

Issue an ES256-signed Mission Passport JWT.

```text
ardur issue --agent-id ID --mission TEXT
            [--allowed-tools NAME ...] [--forbidden-tools NAME ...]
            [--resource-scope PATTERN ...]
            [--max-tool-calls N] [--max-duration-s N]
            [--delegation-allowed] [--max-delegation-depth N]
            [--ttl-s N] [--keys-dir DIR]
```

Prints `{"token": "...", "claims": {...}}` to stdout.

### `ardur verify`

Verify a Mission Passport signature and decode its claims.

```text
ardur verify --token JWT [--keys-dir DIR]
```

### `ardur attest`

Issue a behavioral attestation for a saved session, summarising the receipt
chain.

```text
ardur attest --session SESSION_ID
             [--keys-dir DIR] [--state-dir DIR] [--log-path FILE]
```

## Personal Path

### `ardur hub`

Start the local Ardur Personal Hub HTTP service.

```text
ardur hub [--host HOST] [--port PORT] [--home DIR]
```

See [Personal Hub HTTP API](personal-hub-api.md) for the endpoints exposed.

### `ardur setup`

Configure Ardur Personal on this machine. Generates a Hub token, writes the
local config, and prints the token once for setup.

```text
ardur setup [--host HOST] [--port PORT] [--home DIR]
            [--regen-token] [--print-token]
```

### `ardur status`

Show Hub status — current sessions, latest receipt, adapter availability.

```text
ardur status [--hub-url URL] [--hub-token TOKEN] [--home DIR]
```

### `ardur doctor`

Health-check the local Ardur Personal setup: config presence, Hub
reachability, key material, write permissions.

```text
ardur doctor [--home DIR] [--hub-url URL] [--hub-token TOKEN]
```

### `ardur doctor-claude-code`

Verify the Claude Code plugin and active passport setup. Reports missing
plugin files, missing `claude` binary, missing or stale `active_mission.jwt`.

```text
ardur doctor-claude-code [--home DIR] [--plugin-dir DIR]
```

### `ardur uninstall`

Remove Ardur Personal launch files (LaunchAgent on macOS, etc.) without
deleting the home directory by default.

```text
ardur uninstall [--home DIR] [--remove-home]
```

### `ardur run -- COMMAND ...`

Run a CLI command through the local Hub. Non-interactive only.

```text
ardur run [--hub-url URL] [--hub-token TOKEN] [--home DIR] -- <command>
```

### `ardur desktop-observe`

Record a desktop observation against the Hub. On macOS, autodetects the
foreground app and window title via the Accessibility API when available.

```text
ardur desktop-observe [--hub-url URL] [--hub-token TOKEN] [--home DIR]
                      [--session-id ID] [--app NAME] [--title TEXT]
                      [--no-autodetect]
```

### `ardur personal-native-host`

Run the browser native-messaging host that bridges the browser extension to
the local Hub. Invoked by Chrome/Firefox via the manifest, not by users
directly.

```text
ardur personal-native-host [--hub-url URL] [--hub-token TOKEN] [--home DIR]
                           [--allowed-extension-id ID]
```

### `ardur personal-native-manifest`

Emit a browser native-messaging manifest JSON for installation under the
browser's `NativeMessagingHosts/` directory.

```text
ardur personal-native-manifest --host-path PATH --extension-id ID
                               [--browser chrome|firefox|edge]
```

### `ardur profile init`

Write a starter `ARDUR.md` profile from a built-in template.

```text
ardur profile init --template TEMPLATE
                   [--path PATH] [--force] [--json]
```

Templates: `read-only`, `safe-coding`. Default path: `./ARDUR.md`.

### `ardur protect claude-code`

Compile a Mission Passport (from an `ARDUR.md` profile or from CLI flags) and
write `active_mission.jwt` for the Claude Code plugin to read. Prints the
exact `claude` invocation that pairs the plugin with the active passport.

```text
ardur protect claude-code [--scope DIR] [--profile PATH]
                          [--mode read-only|safe-coding]
                          [--json] [--home DIR] [--plugin-dir DIR]
                          [--keys-dir DIR] [--agent-id ID]
                          [--mission TEXT]
                          [--max-tool-calls N] [--max-duration-s N]
                          [--ttl-s N]
```

Profile mode and CLI mode set the same Mission Passport — the Markdown
profile is a friendly layer over the same capability set.

### `ardur cc-hook`

Implements the Claude Code hook executable invoked by
`plugins/claude-code/hooks/`. Not intended for human invocation; called by
Claude Code with hook-specific stdin payloads.

### `ardur cc-report`

Read a Claude Code receipt chain and emit a human or JSON summary of allow,
deny, and chain-verification outcomes.

```text
ardur cc-report [--home DIR] [--chain-dir DIR] [--keys-dir DIR]
                [--trace TRACE_ID] [--json]
```

## Where to look next

- [`../guides/ardur-personal-hub.md`](../guides/ardur-personal-hub.md) — the
  end-to-end Personal Hub walkthrough.
- [`../../python/README.md`](../../python/README.md) — install + protocol
  quickstart.
- [`../../plugins/claude-code/README.md`](../../plugins/claude-code/README.md) —
  the Claude Code plugin's own README, including receipt verification.
