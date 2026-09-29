# RunTrust Sentinel — Claude Code plugin

Sentinel is [RunTrust](https://app.runtrust.ai)'s governance connector for
Claude Code: a PreToolUse hook that checks every tool call against your
organization's policy and writes an audit trail of decisions to your RunTrust
workspace.

> **Read-only mirror.** This repository is published automatically from
> RunTrust's private source repository. Issues and pull requests here are not
> monitored — reach support through your RunTrust workspace.

## Install

Supported platforms: **Windows** (x64) and **macOS** (Apple Silicon and Intel, detected automatically). The macOS binaries are signed with RunTrust's Apple Developer ID and notarized by Apple. The macOS install is verified end to end on Intel. The Apple Silicon build comes from the same pipeline, where its binaries pass their tests; its install is not yet verified end to end.

In Claude Code:

```
/plugin marketplace add runtrust/runtrust-marketplace
/plugin install sentinel@runtrust
/sentinel:setup '<install-token>' --endpoint <your console's address>
/reload-plugins
```

Copy the `/sentinel:setup` line from the **Install** page of your RunTrust
workspace: it carries your single-use install token and the address of the
console that issued it, so the token is exchanged where it was issued. The
token is consumed by `/sentinel:setup` and cannot be replayed. There is no
default address — without `--endpoint` the setup stops before touching
anything.

The same command works on Windows and macOS. On macOS it downloads the
binaries for your CPU from your console's `/downloads/` and verifies their
checksums before it installs anything.

## Commands

- **`/sentinel:setup '<install-token>' --endpoint <address>`** — connect this
  machine to RunTrust. Downloads the connector binaries from
  `<address>/downloads/` (checksum-verified; on macOS signed and notarized),
  exchanges the token for a tenant-bound credential at the console that issued
  it, and starts the local connector. Works on Windows and macOS (see the
  platform note above).
- **`/sentinel:status`** — show local connector status.
- **`/sentinel:uninstall`** — remove the local connector state.

## Before setup

Installing the plugin is safe and inert: until `/sentinel:setup` runs, the
hook allows every tool call and enforces nothing.

## License

Apache-2.0 — see [LICENSE](https://github.com/runtrust/runtrust-marketplace/blob/master/plugins/sentinel/LICENSE).
