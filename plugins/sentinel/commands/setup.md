---
description: Connect this machine to RunTrust/Sentinel using a one-time install token.
---

Detect the operating system and follow the matching path below.

---

## Windows

Run this exact command via the Bash tool, substituting the user's install token for `$ARGUMENTS`:

`powershell -NoProfile -ExecutionPolicy Bypass -File "${CLAUDE_PLUGIN_ROOT}/scripts/sentinel-setup.ps1" -InstallToken '$ARGUMENTS'`

Then report the setup result (Installed / FirstDecisionConfirmed / Tenant / Decisions URL) to the user. The install token is single-use and secret — never echo it back to the user unredacted, and do not store it.

---

## macOS (darwin)

Run the following three steps in order using the Bash tool.

### Step 1 — Download, verify, and wire the connector

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/sentinel-install.sh" --plugin-root "${CLAUDE_PLUGIN_ROOT}"
```

This downloads and checksum-verifies the signed darwin binaries from `app.runtrust.ai/downloads/` and wires the bash enforcement hook.

### Step 2 — Argv-safe token handoff

The install token must **never** appear on a process command line, in shell history, or in the process environment — it must be fed to the connector via stdin from a 0600 file that is removed immediately.

**2a — Create the token file** (Bash tool):

```bash
p="$HOME/.sentinel/.install-token"; ( umask 177; : > "$p" ); chmod 600 "$p"; echo "$p"
```

This creates the file at the fixed path `~/.sentinel/.install-token` (the `~/.sentinel` directory already exists from Step 1). It prints the absolute path so you have the exact literal for the next step.

**2b — Write the token** (Write tool, NOT shell):

Use the **Write tool** to write the raw `$ARGUMENTS` install token (no trailing newline) to the absolute path printed above (`/Users/<you>/.sentinel/.install-token`). This ensures the secret never enters argv, shell history, or `ps` output.

**2c — Run setup with cleanup trap** (Bash tool):

```bash
p="$HOME/.sentinel/.install-token"; trap 'rm -f "$p"' EXIT; bash "${CLAUDE_PLUGIN_ROOT}/scripts/sentinel-setup.sh" < "$p"
```

The path is re-derived from the same fixed `$HOME/.sentinel/.install-token`, so it resolves identically across tool calls. The `trap` guarantees the file is removed even if the setup command fails.

**Do NOT** use `printf %s '<token>' | bash …` (the token appears on `printf`'s command line and in shell history).
**Do NOT** use `SENTINEL_INSTALL_TOKEN='<token>' bash …` (the token is readable via `/proc/<pid>/environ` and `ps -E`).
**Do NOT** pass the token as an argv to any command.

### Step 3 — Report result

Report the setup result (Installed / Tenant / mode) to the user. The install token is single-use — **never echo it back unredacted** and do not store it.
