# outside-access-guard

Adds "reading outside my workspace goes through me" to DeepSeek Harness, and widens the binary switch of
[dsh-outsideread-switch](https://www.npmjs.com/package/dsh-outsideread-switch) into three modes.

## Background

In `workspace-write` mode the DSH file sandbox **restricts writes but not reads**:

- reading `C:\Windows\win.ini`, listing `C:\`, or reading a file on any drive is allowed outright;
- writes outside the workspace are rejected by the sandbox; `read-only` mode allows reads as well.

So "the model can quietly read the whole machine" is the default behaviour. This plugin hooks the
`tools/pre-execute` waterfall before dispatch and decides allow, ask, or deny according to the mode.

## Three modes

| `mode` | Inside the workspace | Outside the workspace | Meaning |
| --- | --- | --- | --- |
| `deny` | allow | **deny outright** | the "forbid everything" switch |
| `ask` (default) | allow | **approve every call** | sensitive paths need **two** confirmations |
| `allow` | allow | allow | the "allow everything" switch |

The mode has two entry points:

1. **Persistent default**: `mode` in the profile patch, applied on restart;
2. **Runtime switch**: the human command `/outside-access deny|ask|allow|status`.
   Slash commands can only be issued by a human, so the model cannot use them to widen its own access.
   The switch **lives in memory only**; a restart restores the configured default.

```yaml
- id: outside-access-guard
  config:
    mode: ask
```

## Sensitive paths: an extra alert and a second confirmation

An ordinary outside access prompts once (1/1). A path matching a sensitive rule escalates:

1. **Step 1/2**: a separate high-risk alert that names the matched sensitive rule;
2. **Step 2/2**: only after that does the call's ordinary approval appear;
3. both must be approved; rejecting or cancelling either step prevents execution.

Default sensitive rules (override with `sensitivePaths`; an empty array disables the escalation):

```
**/.ssh/**            **/.aws/**            **/.gnupg/**          **/.kube/**
**/.config/gcloud/**  **/.docker/config.json
**/.netrc             **/.git-credentials   **/.npmrc             **/.pypirc
**/.dsh/.credentials.yaml   **/.dsh/sessions/**   **/.dsh/storages/**
**/AppData/Roaming/Microsoft/Credentials/**
**/AppData/Local/Microsoft/Credentials/**
**/AppData/Local/Google/Chrome/User Data/**
**/AppData/Local/Microsoft/Edge/User Data/**
**/AppData/Local/BraveSoftware/**
**/AppData/Roaming/Mozilla/Firefox/Profiles/**
**/id_rsa*  **/id_ed25519*  **/id_ecdsa*  **/*.pfx  **/*.p12
**/Windows/System32/config/**  **/NTDS.dit
**/logins.json  **/key4.db  **/Login Data  **/Local State  **/Cookies
```

Matching uses both the **lexical path and the real path** (after resolving symlinks); it is
case-insensitive on Windows. If you do not want two clicks every time, set
`sensitiveConfirmations: single` for a single but more strongly worded confirmation.

## Coverage

Judged by path arguments:

| Tool | Field |
| --- | --- |
| `read` / `read_image` | `file_path` |
| `grep` / `glob` | `path` (defaults to the workspace root, which is allowed) |
| `working_directory` | `cd` (prevents `cd` outside followed by a relative read) |
| `pwsh` / `bash` / `shell` | `workdir`, plus absolute paths, `..`, `~`, `$env:`, `$HOME`, `%VAR%` in the command text |

Details:

- the boundary is the **session directory at the agent's first call** (pinned before dispatch), so a later `cd` outside does not move the fence;
- `sandboxPolicy.workspaceRoot` is deliberately not used: in a desktop profile it may be the host process directory (the profile), which would mistake the profile for the workspace;
- relative paths resolve against the current session directory; absolute paths are judged directly;
- lexical path and `realpath` are both compared, so a symlink or junction inside the workspace that points outside is caught;
- a path that does not exist resolves its deepest existing ancestor;
- drive-relative paths (`C:foo`) cannot be judged safely and are treated as outside;
- `extraAllowedRoots` explicitly allows additional roots (absolute, or relative to the workspace).

## Configuration

```yaml
- id: outside-access-guard
  config:
    mode: ask                 # deny | ask | allow, default ask
    log: true                 # append decision logs
    logDir: ''                # default <DSH_HOME>/logs/outside-access-guard
    logRetentionDays: 7       # delete logs older than N days (0 = keep forever)
    sensitiveConfirmations: double   # double | single
    sensitivePaths: []        # omit = default rules; [] = disable the sensitive escalation
    extraAllowedRoots: []     # additional allowed roots
    gateShell: true           # inspect shell tools, default true
    gatePathTools: true       # inspect file tools, default true
```

## Logging

Every decision appends one JSONL line to `$DSH_HOME/logs/outside-access-guard/YYYY-MM-DD.log`, split by local date and kept for 7 days (cleaned on process start, then at most every six hours):

```json
{"ts":"2026-10-24T20:38:35.123+08:00","event":"ask","mode":"ask","tool":"read","risk":"normal","agent":"...","reason":"..."}
```

- `event`: `ask` / `deny` / `cancel` / `mode` / `approval` (the outcome);
- only calls that were classified are logged (reads inside the workspace produce nothing);
- a failed write only warns and never affects interception;
- `log: false` disables it, `logDir` changes the directory, `logRetentionDays` changes retention.

## Known limitations

1. **Shell inspection is heuristic, not system-level isolation.** Absolute paths, `..` and common
   environment variables are recognised; string concatenation, double expansion, encoding and
   subprocess scripts still get through. Real reliability requires the sandbox itself to restrict reads.
2. **Only the tool layer is covered.** Attachments, skill loading, session logs, web fetching and other
   host-internal services do not pass through `tools/pre-execute`.
3. **When the approval policy is `never` or no answerer is available**, `ask` fails closed (denied);
   it does not fall through to allow.
4. **Write policy is unchanged**: writes outside the workspace are still rejected by the sandbox;
   `allow` only affects this plugin and does not relax the kernel sandbox.
5. **The mode is process-global**, not per session; the runtime switch is lost on restart.
6. **Known development gap**: the plugin source lives inside the workspace, so the model can rewrite it
   with `write`/`edit` (effective after a restart or hot reload). Before publishing, move the installed
   copy out of the workspace and add self-modification protection.
7. Sensitive rules are a *reminder*, not a guarantee: a user can still approve twice by mistake.
   For paths that must never be read, use `deny` mode or a sandbox policy.

## Verification

```powershell
# Pure classification tests (24) + plugin wiring tests (9)
# Run directly; do not use `node --test` (spawn EPERM inside the sandbox)
node test/classify.test.mjs
node test/apply.test.mjs
```

After installing:

- `/outside-access status` → shows the current mode; the command is registered by the host at startup,
  so plugin changes need a DSH restart;
- read an ordinary file outside the workspace → one approval;
- read `~/.ssh/id_rsa`, a browser `Login Data`, or `.dsh/.credentials.yaml` → two approvals;
- after `/outside-access deny`, reading any outside file → denied outright, no dialog;
- after `/outside-access allow` → no interception.

> `/outside-access` is a host slash command registered only at plugin startup; the runtime switch
> lives in memory and a restart returns to the configured `mode`.

## Install / uninstall

```powershell
# Install (a local directory, or a GitHub / npm package)
dsh plugin --profile desktop add /absolute/path/to/outside-access-guard

# Uninstall
dsh plugin --profile desktop remove outside-access-guard
```

Host-only, zero dependencies, no network requests, no install scripts.

## Difference from the binary switch

`dsh-outsideread-switch` has only "forbidden / allowed", and its state is maintained by a human through
the UI. This plugin adds per-call approval in between and escalates sensitive paths to two confirmations.
Both are tool-layer fences, and both shell restrictions are heuristic;
`dsh-outsideread-switch` has self-elevation protection for its own state file, which this plugin does not
implement yet (see limitation 6).

## License

MIT, see [LICENSE](LICENSE).
