---
description: Connect this machine to RunTrust/Sentinel using a one-time install token.
---

Run this exact command via the Bash tool, substituting the user's install token for `$ARGUMENTS`:

`powershell -NoProfile -ExecutionPolicy Bypass -File "${CLAUDE_PLUGIN_ROOT}/scripts/sentinel-setup.ps1" -InstallToken '$ARGUMENTS'`

Then report the setup result (Installed / FirstDecisionConfirmed / Tenant / Decisions URL) to the user. The install token is single-use and secret — never echo it back to the user unredacted, and do not store it.
