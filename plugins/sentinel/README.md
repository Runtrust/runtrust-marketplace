# RunTrust Sentinel — Claude Code plugin

Sentinel is [RunTrust](https://app.runtrust.ai)'s governance connector for
Claude Code: a PreToolUse hook that checks every tool call against your
organization's policy and writes an audit trail of decisions to your RunTrust
workspace.

> **Read-only mirror.** This repository is published automatically from
> RunTrust's private source repository. Issues and pull requests here are not
> monitored — reach support through your workspace at
> https://app.runtrust.ai.

## Install

In Claude Code:

```
/plugin marketplace add runtrust/runtrust-marketplace
/plugin install sentinel@runtrust
/sentinel:setup '<install-token>'
/reload-plugins
```

Get your single-use install token from the **Install** page of your RunTrust
workspace. The token is consumed by `/sentinel:setup` and cannot be replayed.

## Commands

- **`/sentinel:setup '<install-token>'`** — connect this machine to RunTrust.
  Downloads the signed connector binaries from
  https://app.runtrust.ai/downloads/ (checksum-verified), exchanges the token
  for a tenant-bound credential, and starts the local connector.
- **`/sentinel:status`** — show local connector status.
- **`/sentinel:uninstall`** — remove the local connector state.

## Before setup

Installing the plugin is safe and inert: until `/sentinel:setup` runs, the
hook allows every tool call and enforces nothing.

## License

Apache-2.0 — see [LICENSE](https://github.com/runtrust/runtrust-marketplace/blob/master/plugins/sentinel/LICENSE).
