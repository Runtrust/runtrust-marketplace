---
description: Show the local RunTrust/Sentinel connector status.
---

Detect the operating system and follow the matching path below.

---

## Windows

Run this exact command via the Bash tool:

`powershell -NoProfile -ExecutionPolicy Bypass -File "${CLAUDE_PLUGIN_ROOT}/scripts/sentinel-status.ps1"`

Then report the connector status to the user:
- If the output says "not-setup", tell the user they need to run `/sentinel:setup` with an install token to provision the connector.
- If the connector is set up, report the mode, tenant, and reachability from the StatusJson output.
- Note: `shadow mode active`, `audit-only-allowed`, and `no-bundle` are NORMAL operating states — they are not failures. Only report a problem if the engine or sink is explicitly shown as unreachable (DOWN).
- If the output includes a shim-degraded warning, surface it and suggest checking `~/.sentinel/logs/sentinel-shim.ndjson`.

---

## macOS (darwin)

Run this exact command via the Bash tool:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/sentinel-status.sh" --plugin-root "${CLAUDE_PLUGIN_ROOT}"
```

Then report the connector status to the user:
- If the output says "not-setup", tell the user they need to run `/sentinel:setup` with an install token to provision the connector.
- If the connector is set up, report the mode, tenant, and reachability from the output.
- Note: `shadow mode active`, `audit-only-allowed`, and `no-bundle` are NORMAL operating states — they are not failures. Only report a problem if the engine or sink is explicitly shown as unreachable (DOWN).
- If the output includes a shim-degraded warning, surface it and suggest checking `~/.sentinel/logs/sentinel-shim.ndjson`.
