# Dendrite Configuration

`dendrited` reads its configuration from environment variables at startup, layered onto `RuntimeConfig::development_defaults()`. There is currently no config-file format; environment variables are the only override mechanism.

This is development-time plumbing. Batch 7 packaging should replace ad-hoc environment variables with packaged defaults (`/etc/dendrite`, `/var/lib/dendrite`) and a dedicated `dendrite` service user/group, per [`ROADMAP.md`](ROADMAP.md).

## Storage paths

| Variable | Default | Description |
|---|---|---|
| `DENDRITE_SELF_DB` | `data/self.sqlite3` | Self store (instance identity, signing keys) |
| `DENDRITE_STM_DB` | `data/stm.sqlite3` | Short Term Memory Graph database |
| `DENDRITE_LTM_DB` | `data/ltm.sqlite3` | Long Term Memory Graph database |
| `DENDRITE_INCIDENT_DB` | `data/incidents.sqlite3` | Incidents/evidence database — also backs the vulnerability, CVE, and behaviour-knowledge tables (`VulnerabilityService`/`KnowledgeService` both open this same file; there is no separate vulnerability/knowledge DB path) |
| `DENDRITE_CVE_SNAPSHOT` | `knowledge/cve-snapshot.json` | Bundled CVE/behaviour knowledge, auto-imported once at startup |

If this file exists, it's imported via the same path (and validation) as `vulnerability import` — including the strict `"kind": "graph-relation"` behaviour-condition check documented in `crates/dendrite-cli/CLI.md`. If it's absent, startup continues normally with no CVE knowledge preloaded. If it exists but fails validation, the failure is logged to stderr rather than aborting startup — a deliberately softer failure mode than the CLI's hard rejection, since this runs unattended rather than as an explicit user action. There is currently no bundled default snapshot shipped in the repo; this is the intended integration point for one once packaging (Batch 7) ships real CVE/behaviour data.

## IPC and network

| Variable | Default | Description |
|---|---|---|
| `DENDRITE_SOCKET` | `/tmp/dendrited.sock` | Unix socket path `dendrited` listens on |
| `DENDRITE_MAGI_SOCKET` | `/tmp/dendrite-magi.sock` | Unix socket path `dendrited` connects to for MAGI quorum evaluation (see below) |
| `DENDRITE_GUARD_SOCKET` | `/tmp/dendrite-guard.sock` | Unix socket path `dendrited` connects to for Guard trust/authority checks (see below) |
| `DENDRITE_SOCKET_GROUP` | unset (no group change) | Group ownership applied to the socket |
| `DENDRITE_SOCKET_MODE` | `0660` | Socket file permission mode, octal (`0o` prefix accepted) |
| `DENDRITE_HTTP_ADDR` | `127.0.0.1:8766` | Localhost HTTP API bind address — also serves the live-event WebSocket (see below) |
| `DENDRITE_HTTP_TOKEN_FILE` | `/tmp/dendrite-http.token` | Path `dendrited` writes its HTTP API bearer token to on startup (see "HTTP API authentication" below) |

`DENDRITE_HTTP_ADDR` is silently ignored if it fails to parse as a socket address — the default is kept in that case with no warning printed. `DENDRITE_SOCKET_MODE` is stricter: an unparseable value logs an error and exits with status `2`.

`DENDRITE_SOCKET` is a *systemd-unit-scoped* environment variable on a packaged install (`packaging/dendrited.service` sets it to `/run/dendrite/dendrited.sock`) — it's invisible to an interactive shell, which `dendrite-cli` also reads this same variable from when set. Real Checkpoint-B validation on a packaged `.deb` install confirmed this is exactly the trap it sounds like: `dendrite-cli` with `DENDRITE_SOCKET` unset previously always fell back to the dev default (`/tmp/dendrited.sock`), which never matches a packaged `dendrited`. `dendrite-cli` now checks for `/run/dendrite/dendrited.sock` first (falling back to the dev default only if that's not there — see `crates/dendrite-cli/src/main.rs`), so an operator's `dendrite-cli status`/`health` works against a packaged install with no environment variable to set by hand. The remaining requirement — being in the `dendrite` group, since the socket is `0660`/group-owned (see `DENDRITE_SOCKET_GROUP`/`DENDRITE_SOCKET_MODE` above) — is handled by `packaging/postinst`, which best-effort adds the invoking `sudo` user to that group on install (effective after the next login).

On a packaged install, `/run/dendrite` (holding `dendrited`'s, `dendrite-magi`'s, and `dendrite-guard`'s sockets) is provisioned by a tmpfiles.d snippet (`packaging/dendrite.tmpfiles`, applied via `postinst`) rather than any one unit's own `RuntimeDirectory=`. This was a real bug found during Checkpoint B validation: systemd deletes a `RuntimeDirectory=` entirely when the *first* unit referencing it stops, even while sibling units sharing that name are still running ([systemd/systemd#5394](https://github.com/systemd/systemd/issues/5394)) — so `systemctl restart dendrite-guard` alone used to unlink `dendrited`'s and `dendrite-magi`'s still-listening sockets out from under them. See the three `packaging/*.service` files' own comments for the same reasoning.

The live event stream is a WebSocket upgrade of a normal request to `/ws` on this same address/port — there is no separate `DENDRITE_WS_ADDR` any more (removed as part of Batch 7's "one address, just works" distribution-packaging goal). `dendrited` detects the upgrade (`Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Key` headers on a `GET /ws` request) itself on its ordinary HTTP accept loop and performs the handshake by hand rather than via a second listener.

### HTTP API authentication

Both the HTTP API and the `/ws` WebSocket upgrade require a bearer token. The origin allowlist above only ever restricted requests a *browser* sends (it checks the `Origin` header, which any non-browser HTTP client simply omits), so it was never a real access control on its own — the token is what actually gates the API now.

`dendrited` generates the token once, the first time it starts against a given `self.sqlite3` (persisted there — like the instance identity and signing key — so it's stable across restarts, not rotated per-boot), and writes it out to the path in `DENDRITE_HTTP_TOKEN_FILE` above with the same group/mode as the Unix socket (see `DENDRITE_SOCKET_GROUP`/`DENDRITE_SOCKET_MODE`). It's deliberately **not** served automatically over the HTTP API itself, since that's the port with the no-auth-for-non-browser-clients problem this closes — the only way to retrieve it is over the Unix socket, via `dendrite-cli http-token` (see `crates/dendrite-cli/README.md`).

A request authenticates with either:
- an `Authorization: Bearer <token>` header, for ordinary HTTP requests, or
- a `?token=<token>` query parameter, for the WebSocket handshake, since a browser can't set custom headers on it, and for the packaged UI's cross-origin requests generally — a custom header would force a CORS preflight, and this server intentionally has no `OPTIONS`/preflight handling (see `crates/dendrited/src/http.rs`), so a query parameter keeps every request "simple" under the CORS spec.

Neither UI build ever requires copy-pasting the token in by hand more than once, if at all:
- **Local dev** (`npm run dev`): the Vite dev-proxy (`ui/vite.config.ts`) reads the token file directly off disk (it runs in Node, on the same machine as `dendrited`) and injects the `Authorization` header into every proxied request itself. Nothing in the browser ever needs the token.
- **Packaged/production** (`ui/dist`, served by `dendrite-ui-server`): the browser has no such proxy, so the UI shows a one-time token-entry prompt the first time it gets a `401` (`ui/src/components/TokenGate.tsx`), then keeps the token in `localStorage` and appends it as `?token=` to every request/WebSocket URL from then on (`ui/src/api/token.ts`).

### The UI, and its own process

`dendrited` itself never serves the UI. The built UI (`ui/dist`) is served by a separate binary/systemd unit, `dendrite-ui-server`/`dendrite-ui.service` — a small, unprivileged static-file server with no dependency on `dendrited` being up to start, so an operator can `systemctl disable --now dendrite-ui` independently of the daemon. See `crates/dendrite-ui-server/README.md` for its own environment variables (`DENDRITE_UI_DIR`, `DENDRITE_UI_ADDR`, `DENDRITE_UI_API_ORIGIN`).

Because the UI's static assets and `dendrited`'s API/WebSocket can live on different origins/ports, the UI's own JS talks to `dendrited` cross-origin — that's what the CORS allowlist above is for. Where that origin lives is **not** baked into the JS bundle at build time any more: `dendrite-ui-server` serves a small runtime config document, `/dendrite-config.json`, generated from its own `DENDRITE_UI_API_ORIGIN` env var, and the UI fetches it once on load (`ui/src/api/runtimeConfig.ts`) before rendering. This means the same build of `ui/dist` works for every deployment topology — same-origin behind a reverse proxy, split-origin with `dendrited` on another host or port, or a future multi-host "herd" deployment — and repointing it is a `DENDRITE_UI_API_ORIGIN` change plus a restart of `dendrite-ui.service`, not a rebuild.

| Runtime variable | Default | Set to (packaged, split-origin) |
|---|---|---|
| `DENDRITE_UI_API_ORIGIN` | unset (same-origin as the UI itself) | `http://<dendrited-host>:8766` |

Set it in `/etc/dendrite/dendrite-ui.env` (installed from `packaging/dendrite-ui.env.example`, a conffile — see `packaging/dendrite-ui.service`'s `EnvironmentFile=`). Local dev (`npm run dev`) leaves it unset — `ui/public/dendrite-config.json` (served verbatim by Vite) reports `apiOrigin: null`, and Vite's own dev-proxy (`ui/vite.config.ts`) forwards `/api`/`/ws` to `dendrited` on the same apparent origin, so no cross-origin call ever happens there either. This isn't a security boundary in either form — whoever can write to the served directory, or set the unit's environment, already controls everything the UI does — just an ergonomics fix over the old build-time-baked approach.

### MAGI, and its own process

MAGI quorum evaluation (the Host/User/Environment votes an action proposal needs before it can execute) runs in a separate process, `dendrite-magi`/`dendrite-magi.service`, reached over a Unix socket — the same process-separation reasoning as the UI split above, and the same one behind the Guard split just below: action authority shouldn't be reachable in-process from wherever a compromise of `dendrited` itself might land. See `crates/dendrite-magi/README.md`.

`dendrited` talks to it as a client (`MagiIpcClient`) and is deliberately **fail-closed**: if `dendrite-magi` is unreachable, times out, or isn't running at all, every seat comes back `abstain` rather than the request hanging or silently defaulting to approval. Under the default quorum policy (2 approvals required, an abstain counting toward neither approval nor denial) this means an action can never complete while `dendrite-magi` is down — it is denied, not silently allowed, and not stuck waiting. An operator can see this happening in the CLI's `MAGI:` section of `actions evaluate`/`actions <ID>` output, where each seat's reason string reads `dendrite-magi is unreachable: ...` instead of a real evaluation.

| Variable | Default | Description |
|---|---|---|
| `DENDRITE_MAGI_HOST_SOURCE` | `internal` | Which evaluator backs the Host seat |
| `DENDRITE_MAGI_USER_SOURCE` | `internal` | Which evaluator backs the User seat |
| `DENDRITE_MAGI_ENVIRONMENT_SOURCE` | `internal` | Which evaluator backs the Environment seat |

`internal` (the only value implemented today) is `dendrite-magi`'s own built-in rule-based evaluator. These three variables exist now, ahead of that support actually existing, so that hooking an MCP-connected AI agent up to a seat — letting a company's own infrastructure-aware model act as that seat's MAGI vote, as a full replacement for the internal evaluator's authority over that seat, rather than merely advising it — is a configuration change later rather than a code change today. `dendrite-magi` refuses to start if any of these is set to anything other than `internal`, on purpose, rather than silently falling back to the internal evaluator for that seat. See `docs/ROADMAP.md` for the current status of the MCP-backed evaluator work itself (not yet built).

### Guard, and its own process

Guard (the trust state / integrity findings that decide whether `dendrited` currently has authority to act at all) runs in a separate process, `dendrite-guard`/`dendrite-guard.service`, reached over a Unix socket — the same process-separation reasoning as MAGI just above, applied to the one subsystem it matters most for: a compromise of `dendrited` itself must not be able to reach the thing that decides whether `dendrited` still has authority. See `crates/dendrite-guard/README.md`.

Unlike MAGI (a stateless per-request vote), Guard owns real persistent state — `guard.sqlite3` now lives with `dendrite-guard`, not `dendrited` (there is no more `DENDRITE_GUARD_DB` on `dendrited`'s side; see `crates/dendrite-guard/README.md` for that variable, which now belongs to `dendrite-guard` itself). In a packaged install, `dendrite-guard` also runs as its own dedicated system user rather than sharing `dendrited`'s — process separation alone doesn't stop a compromised `dendrited` from writing to Guard's state directly if the two share a user and a writable directory, so `dendrite-guard`'s own `StateDirectory=` is locked down to that user alone (mode `0700`, no group access). See `crates/dendrite-guard/README.md`'s "Privilege separation" section for the full design, including how `dendrited` still reaches Guard's *socket* despite this.

`dendrited` talks to it as a client (`GuardIpcClient`) and is deliberately **fail-closed**, but differently from MAGI: if `dendrite-guard` is unreachable, times out, or isn't running, the trust state reads as **`Compromised`** and every authority check as **`Deny`** — not abstain, and not a hang. Guard has exactly one voice on trust rather than MAGI's three-way vote, so there's no quorum for "unreachable" to defer to; collapsing straight to the same denial a real detected compromise produces is the only fail-closed answer available. Reading Guard's status or findings (`dendrite guard`) behaves differently again — it fails the request outright rather than reporting a synthetic status, because those calls also feed signed Antiserum attestations, and a fabricated "unreachable" status could misrepresent host integrity in an exported package. `DENDRITE_GUARD_SOCKET` is listed under "IPC and network" above.

`dendrite-guard` also owns a signed integrity manifest: `dendrite guard baseline`/`dendrite guard verify` hash a configured set of paths (`DENDRITE_GUARD_WATCH_PATHS`, `dendrite-guard`'s own env var, never accepted over the wire from `dendrited`) and compare current hashes against a stored, signed baseline. See `crates/dendrite-guard/README.md`'s "Integrity manifest" section for the full design, including why Guard signs with its own key rather than `dendrited`'s.

Verification is not only triggered manually: `dendrite-guard` also runs it automatically, in a background thread that verifies once at startup and then every `DENDRITE_GUARD_VERIFY_INTERVAL_SECONDS` (default `300`) — same env-var-configuration pattern as everything else here. A detected mismatch now has real consequences rather than just being reported: it's recorded as an `IntegrityFinding` (deduplicated, so a persistent unresolved mismatch produces one finding, not one per tick) and escalates trust state, via a monotonic rule that never automatically moves trust back toward `Trusted`. See `crates/dendrite-guard/README.md`'s "Integrity manifest" section for the severity heuristic and escalation rules.

Getting back to `Trusted` is its own explicit, two-step operation: `dendrite guard recover begin` writes a one-time token into Guard's own privilege-separated state directory (never returned over the wire, since a compromised `dendrited` relays every response) and `dendrite guard recover complete <TOKEN>` — with the token read directly off the host, not through `dendrited` — verifies it, re-baselines against current content, and restores `Trusted`. See `crates/dendrite-guard/README.md`'s "Recovery" section for why this needs authentication beyond ordinary socket reachability.

## Telemetry collectors

| Variable | Default | Description |
|---|---|---|
| `DENDRITE_FANOTIFY` | `true` | Enable the fanotify filesystem collector. This is opt-**out**, not opt-in — set to a non-truthy value (`0`, `false`, etc.) to disable. Truthy values: `1`, `true`, `yes`, `on` (case-insensitive) |
| `DENDRITE_EBPF` | `true` | Enable the eBPF process/network collector. Also opt-**out**, like fanotify above (not opt-in) — set to a non-truthy value to disable. Same truthy parsing. Failing to load (missing object, missing capabilities) falls back to `/proc` polling rather than blocking startup — same graceful-fallback behaviour as fanotify |
| `DENDRITE_EBPF_OBJECT` | `ebpf/dendrite-ebpf/target/bpfel-unknown-none/release/dendrite-ebpf` | Path to the compiled eBPF object to load when `DENDRITE_EBPF` is enabled |
| `DENDRITE_WATCH_MOUNTS` | unset (empty) | Colon-separated list of mount points to *restrict* fanotify to. Unset/empty means every real mount, auto-discovered from `/proc/self/mountinfo` (pseudo-filesystems like `proc`/`sysfs`/`cgroup` are always skipped). This narrows discovery, it does not add to it — see the section below |
| `DENDRITE_WATCH_INCLUDE_PATHS` | unset (empty) | Colon-separated list of *specific extra paths* to mark, in addition to whatever `DENDRITE_WATCH_MOUNTS` covers — for a path whose mount you don't otherwise want fully watched. Marked directory-by-directory (capped at 4,096 directories), not filesystem-wide |
| `DENDRITE_WATCH_EXCLUDE_PATHS` | unset (empty) | Colon-separated list of path prefixes to exclude from fanotify events, applied by path component (so `/etc` excludes `/etc/passwd` but not `/etc-backup/passwd`) |
| `DENDRITE_TELEMETRY_INTERVAL_SECONDS` | `5` | Polling interval for fallback collectors, in seconds (minimum enforced value is `1`). Also the cadence for fanotify's periodic mount rescan — see below |

eBPF and fanotify are both opt-out now, not opt-in — a fresh `dendrited` with no environment overrides watches every real mount and collects process/network telemetry via eBPF by default, falling back gracefully (to `/proc` polling, or filesystem polling respectively) wherever either one can't actually load. See [`TELEMETRY.md`](../crates/dendrited/TELEMETRY.md) for collector precedence and fallback behaviour, and the required capability set (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_DAC_READ_SEARCH`) for enabling eBPF/fanotify.

### How fanotify decides what to watch

By default (no configuration at all), Dendrite watches every real, currently-mounted filesystem — the same "watch everything by default" posture a real EDR/AV product takes, not a hand-maintained path list. Concretely, at startup and on every periodic rescan:

1. `/proc/self/mountinfo` is read and parsed into (mount point, filesystem type) pairs.
2. Any pseudo/virtual filesystem type is dropped — `proc`, `sysfs`, `cgroup`/`cgroup2`, `devpts`, `devtmpfs`, `debugfs`, `tracefs`, `securityfs`, `pstore`, `autofs`, `mqueue`, `hugetlbfs`, `binfmt_misc`, `configfs`, `fusectl`, `bpf`, `nsfs`, `rpc_pipefs`/`sunrpc`, `efivarfs`. Deliberately **not** dropped: `tmpfs` (backs real, security-relevant paths like `/tmp` and `/dev/shm`) and `overlay` (what container filesystems use).
3. If `DENDRITE_WATCH_MOUNTS` is set, the discovered list is narrowed to just those mount points.
4. Each remaining mount gets a single `FAN_MARK_FILESYSTEM` mark — one kernel-level call per mount, not a directory-by-directory walk. This is why the old `DENDRITE_WATCH_PATHS`/directory-cap design is gone: `FAN_MARK_FILESYSTEM` covers the whole mount, so it's only correct to use when the entry genuinely *is* a mount point (using it on an arbitrary subtree would silently widen coverage to that subtree's whole filesystem).
5. `DENDRITE_WATCH_INCLUDE_PATHS` entries are marked separately, directory-by-directory (the old per-path approach), for adding specific coverage without watching an entire otherwise-unwatched mount. Skipped automatically if the path's mount is already covered by step 4.
6. On every telemetry interval tick, `/proc/self/mountinfo` is re-read and any newly-appeared mount (a USB drive, a new container's overlay mount) is marked the same way — this is coverage maintenance only; a new mount appearing does not itself generate an observation.
7. `DENDRITE_WATCH_EXCLUDE_PATHS` is applied last, as a userspace filter on already-captured events, before they become observations — it has no effect on what gets *marked*, only on what gets discarded afterward. Since a mount-level watch has no subtree granularity of its own, this is the main lever for "watch everything except X" (e.g. `/proc:/sys:/tmp:/run`, though the pseudo-filesystem list above already covers the first two automatically).

**Collisions are rejected, not silently resolved.** If any `DENDRITE_WATCH_INCLUDE_PATHS` entry and any `DENDRITE_WATCH_EXCLUDE_PATHS` entry are equal, or one is a path-component ancestor of the other, fanotify refuses to start (falls back to polling, with the conflict named in the fallback status detail) rather than picking a winner — silently resolving it either way would make it easy to believe a path is covered when it isn't, or vice versa.

**Two things are always on, deliberately not configurable:**
- **Self-exclusion.** Events generated by Dendrite's own PID are filtered out — its own writes to `stm.sqlite3`/`ltm.sqlite3`/`incidents.sqlite3`/`guard.sqlite3` would otherwise be watched and re-observed, a real amplification loop confirmed in practice, not just theoretical. This is scoped by *PID*, not by excluding those paths — a path-based exclude would also blind Dendrite to some other process tampering with those same files, which is exactly the kind of thing worth catching. There's no legitimate reason to want this off, so it isn't a setting.
- **`FAN_UNLIMITED_QUEUE`/`FAN_UNLIMITED_MARKS`** at `fanotify_init`, replacing the kernel's default 16,384-event queue cap and 8,192-mark cap. Both already require `CAP_SYS_ADMIN`, already mandatory for fanotify at all, so this asks nothing new of the operator. Without `FAN_UNLIMITED_QUEUE` specifically, the kernel can silently drop events once its queue fills, before Dendrite ever sees them — invisible to every metric Dendrite itself reports.

`FAN_MARK_FILESYSTEM` only covers the *one* mounted filesystem containing the marked path — a separately mounted `/home`, or a container's overlay/bind mount, is its own entry in the discovered/restricted mount list, not automatically covered by watching `/`.

## Example: development startup

Since `DENDRITE_FANOTIFY` and `DENDRITE_EBPF` are both on by default now, neither needs to be set explicitly — both kept below only to match the historical `DEVELOPMENT.md` Section 4 configuration for reference. `DENDRITE_WATCH_MOUNTS`/`DENDRITE_WATCH_INCLUDE_PATHS` are optional; unset means "every real mount":

```bash
DENDRITE_SOCKET_GROUP=dendrite \
DENDRITE_SOCKET_MODE=0660 \
DENDRITE_EBPF=1 \
target/debug/dendrited
```

All other values fall back to `RuntimeConfig::development_defaults()`.

`scripts/launch_host_a.sh` wraps exactly this configuration (plus explicit DB/socket/port paths) as the primary, repo-based instance, and is the preferred way to start it over typing the block above by hand. It takes a `--cleanup` flag that deletes `data/` (all DBs, the Antiserum package store, and any imported/exported artifacts) without starting the daemon.

## Running a second (or third, or Nth) instance on one machine

`scripts/launch_host_XYZ.sh [HOST_NAME]` starts an additional, fully independent instance entirely outside the repository (default location `~/dendrite-hosts/<HOST_NAME>`, default `HOST_NAME=b`), for cross-host/Antiserum testing without needing a second machine or VM — see the "Second-instance Antiserum validation" note in `ROADMAP.md` for why this is sufficient. It sets every path/socket/port variable in this document explicitly, so it never collides with `launch_host_a.sh`. For any `HOST_NAME` other than `b` you must set `DENDRITE_HOST_HTTP_PORT` yourself (it covers both HTTP and the `/ws` WebSocket upgrade, merged onto the same port — see above), so that adding a third or fourth host is always an explicit, collision-free choice rather than a guess. It also supports `--cleanup` (delete that host's `data/` only) and `--remove-host` (delete that host's entire folder, for tearing one down completely). Run either script with `--help` for the full option list.