---
description: Remove the local RunTrust/Sentinel connector state from this machine.
---

Detect the operating system and follow the matching path below.

---

## Windows

Run this exact command via the Bash tool:

`powershell -NoProfile -ExecutionPolicy Bypass -File "${CLAUDE_PLUGIN_ROOT}/scripts/sentinel-uninstall.ps1"`

Then confirm removal to the user: the connector binaries, config, and logs have been removed from `~/.sentinel`, and the cc-hook has been unwired from `~/.claude/settings.json`. Remind the user that to remove the plugin itself (not just the connector), they should run `/plugin uninstall sentinel`.

---

## macOS (darwin)

Run this exact command via the Bash tool:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/sentinel-uninstall.sh" --home "$HOME/.sentinel" --plugin-root "${CLAUDE_PLUGIN_ROOT}"
```

Then confirm removal to the user: the connector binaries, config, and logs have been removed from `~/.sentinel`. The bash shim manifest (`hooks.json`) is intentionally left in place — with no config present the shim cleanly no-ops (allows all tool calls), so no CC restart is required. Remind the user that to remove the plugin itself (not just the connector), they should run `/plugin uninstall sentinel`.
