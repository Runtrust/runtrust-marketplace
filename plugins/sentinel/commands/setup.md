---
description: Connect this machine to RunTrust/Sentinel with the one-command install from your console's Install page (the install token and the console's address).
---

The arguments to this command are: `$ARGUMENTS`

They come from the console's Install page as `'<install-token>' --endpoint <console-address>`. Split them:

- **TOKEN** — the first argument, with any surrounding quotes removed. It is single-use and secret: never echo it, never store it, never write it anywhere except the token file in the macOS path below.
- **ENDPOINT** — the value after `--endpoint`: the address of the console that issued the token (for example `https://eu1.runtrust.ai`). If there is no `--endpoint`, run the command below anyway **without** the endpoint argument: the script stops with "no endpoint given — copy the command from your console's Install page", and that message is the whole answer. Never invent, guess or default the endpoint.

Detect the operating system and follow the matching path below.

---

## Windows

Run this exact command via the Bash tool, substituting TOKEN and ENDPOINT:

`powershell -NoProfile -ExecutionPolicy Bypass -File "${CLAUDE_PLUGIN_ROOT}/scripts/sentinel-setup.ps1" -InstallToken 'TOKEN' -Endpoint 'ENDPOINT'`

Then report the setup result (Installed / FirstDecisionConfirmed / Tenant / Endpoint / Decisions URL) to the user. The install token is single-use and secret — never echo it back to the user unredacted, and do not store it.

---

## macOS (darwin)

Run the following three steps in order using the Bash tool. If Step 1 fails, stop and report its message; do not continue to Step 2.

### Step 1 — Download, verify, and wire the connector

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/sentinel-install.sh" --plugin-root "${CLAUDE_PLUGIN_ROOT}" --endpoint 'ENDPOINT'
```

This downloads and checksum-verifies the signed darwin binaries from `ENDPOINT/downloads/` and wires the bash enforcement hook. Without an endpoint it stops before downloading anything.

### Step 2 — Argv-safe token handoff

The install token must **never** appear on a process command line, in shell history, or in the process environment — it must be fed to the connector via stdin from a 0600 file that is removed immediately.

**2a — Create the token file** (Bash tool):

```bash
p="$HOME/.sentinel/.install-token"; ( umask 177; : > "$p" ); chmod 600 "$p"; echo "$p"
```

This creates the file at the fixed path `~/.sentinel/.install-token` (the `~/.sentinel` directory already exists from Step 1). It prints the absolute path so you have the exact literal for the next step.

**2b — Write the token** (Write tool, NOT shell):

Use the **Write tool** to write TOKEN alone — the bare install token, without its quotes, without `--endpoint` or anything else, and with no trailing newline — to the absolute path printed above (`/Users/<you>/.sentinel/.install-token`). This ensures the secret never enters argv, shell history, or `ps` output.

**2c — Run setup with cleanup trap** (Bash tool):

```bash
p="$HOME/.sentinel/.install-token"; trap 'rm -f "$p"' EXIT; bash "${CLAUDE_PLUGIN_ROOT}/scripts/sentinel-setup.sh" --endpoint 'ENDPOINT' < "$p"
```

The path is re-derived from the same fixed `$HOME/.sentinel/.install-token`, so it resolves identically across tool calls. The `trap` guarantees the file is removed even if the setup command fails. The token is exchanged at ENDPOINT — the console that issued it — and the connector binds to the address that console reports.

**Do NOT** use `printf %s '<token>' | bash …` (the token appears on `printf`'s command line and in shell history).
**Do NOT** use `SENTINEL_INSTALL_TOKEN='<token>' bash …` (the token is readable via `/proc/<pid>/environ` and `ps -E`).
**Do NOT** pass the token as an argv to any command.

### Step 3 — Report result

Report the setup result (Installed / Tenant / endpoint / environment) to the user. The install token is single-use — **never echo it back unredacted** and do not store it.
