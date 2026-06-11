---
description: Remove the local RunTrust/Sentinel connector state from this machine.
---

Run this exact command via the Bash tool:

`powershell -NoProfile -ExecutionPolicy Bypass -File "${CLAUDE_PLUGIN_ROOT}/scripts/sentinel-uninstall.ps1"`

Then confirm removal to the user: the connector binaries, config, and logs have been removed from `~/.sentinel`, and the cc-hook has been unwired from `~/.claude/settings.json`. Remind the user that to remove the plugin itself (not just the connector), they should run `/plugin uninstall sentinel`.
