# Historical runner experiment setup

Extracted from development-standards `docs/pc-setup.md` at
1f00db36343f39a0666007a417f17fa49a274101 on 19 November 2026. Original
section preserved below for provenance. Its “current experiment” pins describe
that historical experiment; they are not the current package prerequisites.

For current advisory installation, update, uninstall and recovery use
[project-owner.md](project-owner.md). The package requires Python>=3.12.
Generic PC tooling remains in the shared
[PC setup guide](https://github.com/maxxab/development-standards/blob/main/docs/pc-setup.md).
There is one canonical shared agent-runner skill; no skill is copied here.

This is historical guidance, not a request to sign in, inspect credentials or
run a probe. The current first-release [handoff](handoffs/2026-11-19-first-release.md)
records an unresolved authenticated, bounded real-model route. The old tokenless
loopback fixture and NetworkMode=none do not satisfy that gate. Reuse no consumed
allowance and change no account/profile/network settings from this document.

## Preserved historical section

## Agent runner pre-implementation setup

The shared PC prerequisite installer is `bootstrap.py setup-pc` (or `devstandards setup-pc`); it dispatches to `pc_setup.py`. `setup-pc.ps1` is the Windows helper. The dedicated [agent_runner](https://github.com/maxxab/agent_runner) repository owns runner code and release gates. Read the canonical [agent-runner skill](https://github.com/maxxab/development-standards/blob/main/skills/agent-runner/SKILL.md) for explicit project-local installation; PC setup does not activate a runner.

Shared setup supplies the generic development tools above. Runner experiments additionally need:

- Linux or WSL2 with Python 3.10+ and a working, separately provisioned container engine. Docker is not currently a setup catalog entry, and setup does not start its services.
- An isolated Python environment containing the selected SDK/runtime pair. The current experiment pins `openai-codex==0.167.0` and `openai-codex-cli-bin==0.167.0`, with resolved dependencies and hashes retained in its private evidence. These are experiment pins, not a global CLI upgrade or an installed runner feature.
- Disposable source fixtures, a private runtime profile outside the repository, and explicit time, turn and allocation limits. Retain completed evidence and consumed allowance when resuming; a new chat or login does not reset limits.

Keep SDK packages and probe scripts outside the shared checkout until runner packaging is implemented. Reuse an existing verified environment instead of reinstalling it. Ordinary standards/setup commands remain usable without the SDK. Do not add account credentials to the catalog or automate the account setting below.

### Enable ChatGPT device-code sign-in

For the selected ChatGPT subscription flow, enable the account prerequisite before requesting a code:

1. Open ChatGPT **Settings → Security and login** (some versions label this **Security**).
2. Under **App security**, enable **“Enable device code sign-in for Codex, Excel, PowerPoint, and Word.”** This was the last option in the user-provided screenshot on 10 November 2026; identify it by name, since its position can change. Managed workspaces may require an administrator to enable device-code login in workspace permissions.
3. Start sign-in from the intended runtime/profile. For a normal terminal CLI, use `codex login --device-auth`. For the isolated runner experiment, use the pinned SDK's `login_chatgpt_device_code()` in its dedicated runtime container/profile; the default host CLI login does not authenticate that separate profile.
4. Open the verification URL returned by that request, complete the browser sign-in, and enter its fresh one-time code. Keep the requesting process alive until it reports success. Opening `auth.openai.com` by itself does not bind a login to a runtime. If the request expired or was stopped, reconcile it before starting another authorized request.
5. Confirm completion in the originating runtime: the SDK login result must report success, or use `codex login status` in the same CLI profile. A browser success page alone is insufficient evidence for a stopped runtime.

This is a ChatGPT account setting; no local Codex configuration change is normally required for the toggle. Device codes are useful for a headless container whose browser callback is unavailable. Authentication is needed for live model calls; document review and offline fixture checks do not need it. The code flow is a sign-in method, not a requirement of the runner architecture. See the [official authentication guide](https://learn.chatgpt.com/docs/auth#preferred-device-code-authentication-beta).

Reuse the dedicated profile's cached sign-in on later authorized runs; Codex normally refreshes valid ChatGPT sessions during use. Reauthenticate only when the runtime requires it. Keep the profile private (0700 directory and 0600 credential file on Linux), outside source, reports and check/test containers. Never paste a code or credential into documentation, copy a personal Codex profile into a fixture, or inspect token contents to prove sign-in. See [official credential storage and caching guidance](https://learn.chatgpt.com/docs/auth#login-caching).

Successful authentication completes one prerequisite. It does not prove model access, isolation, child creation, accounting or recovery; the plan's feasibility checks establish those separately.
