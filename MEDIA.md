# Media

This Phase 0 shell includes a small set of starter recordings for the public
repo.

These are terminal recordings in asciinema `.cast` format. They are useful for
showing the product direction now, while rendered GIF or MP4 versions and
broader walkthroughs are prepared later.

## Included In This Pack

- `media/casts/ARDUR-CAP-001-mission-declaration.cast`
  Mission declaration and binding. Archival walkthrough cast. `framework-live`
- `media/casts/ARDUR-CAP-002-tool-policy.cast`
  Tool allow and deny enforcement. Archival walkthrough cast. `framework-live`
- `media/casts/ARDUR-CAP-003-resource-scope.cast`
  Resource scope enforcement. Archival walkthrough cast. `framework-live`
- `media/casts/ARDUR-CAP-014-active-revocation.cast`
  Active revocation. Archival walkthrough cast. `foundation`

## Notes

- These files are sanitized copies of walkthrough recordings from the
  current Ardur implementation lineage.
- They are starter media assets, not the whole proof story. The word
  "proof" is reserved here for media that lands after the code lift and
  carries a rerunnable verifier path — see the archival-status note below.
- Historical live-governance-demo recordings should not be treated as current
  canonical proof.
- Selected recordings should use Ardur public naming in terminal output,
  capability IDs, and artifact paths.
- Rendered preview assets and broader framework walkthroughs are still coming.

### Archival status — not re-runnable from this repo today

These casts capture terminal sessions executed against the private runtime
before the public code lift. Internally they reference commands, scripts,
and artifact paths (`docs/scripts/run_live_core_capability_proof.py`,
`docs/proof/*`, `examples/live-governance/*`) that have **not** yet been
imported into this public repo. Treat them as **archival recordings**, not
as "run these yourself" reproducers.

The re-runnable proof path lands alongside the Phase 1 code lift per
[docs/public-import-plan.md](docs/public-import-plan.md). When the scripts
and artifact paths referenced in these casts are public, the casts will be
re-recorded against the renamed Ardur runtime and this caveat will be
removed.

## Suggested Next Media Drops

- a rendered public-safe walkthrough for the live governance flow
- a Claude Code hook walkthrough
- an OpenAI Agents SDK example
- a Google ADK example
