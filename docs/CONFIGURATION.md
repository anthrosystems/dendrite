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
| `DENDRITE_GUARD_DB` | `data/guard.sqlite3` | Guard trust state / integrity findings database |
| `DENDRITE_CVE_SNAPSHOT` | `knowledge/cve-snapshot.json` | Bundled CVE/behaviour knowledge, auto-imported once at startup |

If this file exists, it's imported via the same path (and validation) as `vulnerability import` — including the strict `"kind": "graph-relation"` behaviour-condition check documented in `CLI.md`. If it's absent, startup continues normally with no CVE knowledge preloaded. If it exists but fails validation, the failure is logged to stderr rather than aborting startup — a deliberately softer failure mode than the CLI's hard rejection, since this runs unattended rather than as an explicit user action. There is currently no bundled default snapshot shipped in the repo; this is the intended integration point for one once packaging (Batch 7) ships real CVE/behaviour data.

## IPC and network

| Variable | Default | Description |
|---|---|---|
| `DENDRITE_SOCKET` | `/tmp/dendrited.sock` | Unix socket path for `dendrite-cli` IPC |
| `DENDRITE_SOCKET_GROUP` | unset (no group change) | Group ownership applied to the socket |
| `DENDRITE_SOCKET_MODE` | `0660` | Socket file permission mode, octal (`0o` prefix accepted) |
| `DENDRITE_HTTP_ADDR` | `127.0.0.1:8766` | Localhost HTTP API bind address — also serves the live-event WebSocket (see below) |
| `DENDRITE_UI_DIR` | unset (daemon serves no UI) | Directory containing the built UI (`ui/dist`) to serve as static files alongside the API. The packaged `.deb` sets this to `/usr/share/dendrite/ui`; local dev leaves it unset and runs `npm run dev`'s own Vite server instead (see `ui/vite.config.ts`'s proxy config) |

`DENDRITE_HTTP_ADDR` is silently ignored if it fails to parse as a socket address — the default is kept in that case with no warning printed. `DENDRITE_SOCKET_MODE` is stricter: an unparseable value logs an error and exits with status `2`.

When `DENDRITE_UI_DIR` is set, any `GET` request that isn't `/api/...` or the `/ws` upgrade is served from that directory: a request matching a real file gets that file (with a content type inferred from its extension); anything else — a client-side route like `/incidents/123`, a bare `/` — falls back to `index.html` so the UI's own router handles it, the same convention as any single-page-app static host. A request that resolves (after following `..` segments) to somewhere outside `DENDRITE_UI_DIR` is rejected the same way — it falls back to `index.html` rather than ever reading the escaped path.

The live event stream is a WebSocket upgrade of a normal request to `/ws` on this same address/port — there is no separate `DENDRITE_WS_ADDR` any more (removed as part of Batch 7's "one address, just works" distribution-packaging goal; see `ROADMAP.md`'s Batch 10 note on the merge). `dendrited` detects the upgrade (`Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Key` headers on a `GET /ws` request) itself on its ordinary HTTP accept loop and performs the handshake by hand rather than via a second listener.

Neither the HTTP API nor the `/ws` WebSocket endpoint currently perform any request authentication; the HTTP API (and, as of the port merge, `/ws` too) only enforces a CORS origin allowlist against the UI dev server origins. See the "Deliberately deferred" note in [`ROADMAP.md`](ROADMAP.md) Checkpoint A — this is being treated as an explicit pre-MCP item rather than an oversight, but it's worth keeping the endpoint bound to loopback until it's addressed.

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

eBPF and fanotify are both opt-out now, not opt-in — a fresh `dendrited` with no environment overrides watches every real mount and collects process/network telemetry via eBPF by default, falling back gracefully (to `/proc` polling, or filesystem polling respectively) wherever either one can't actually load. See [`TELEMETRY.md`](TELEMETRY.md) for collector precedence and fallback behaviour, and the required capability set (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_DAC_READ_SEARCH`) for enabling eBPF/fanotify.

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

Since `DENDRITE_FANOTIFY` and `DENDRITE_EBPF` are both on by default now, neither needs to be set explicitly — both kept below only to match the historical `TESTS.md` Section 4 configuration for reference. `DENDRITE_WATCH_MOUNTS`/`DENDRITE_WATCH_INCLUDE_PATHS` are optional; unset means "every real mount":

```bash
DENDRITE_SOCKET_GROUP=dendrite \
DENDRITE_SOCKET_MODE=0660 \
DENDRITE_EBPF=1 \
target/debug/dendrited
```

All other values fall back to `RuntimeConfig::development_defaults()`.

`scripts/launch_host_a.sh` wraps exactly this configuration (plus explicit DB/socket/port paths) as the primary, repo-based instance, and is the preferred way to start it over typing the block above by hand. It takes a `--cleanup` flag that deletes `data/` (all DBs, the Antiserum package store, and any imported/exported artifacts) without starting the daemon.

## Running a second (or third, or Nth) instance on one machine

`scripts/launch_host_XYZ.sh [HOST_NAME]` starts an additional, fully independent instance entirely outside the repository (default location `~/dendrite-hosts/<HOST_NAME>`, default `HOST_NAME=b`), for cross-host/Antiserum testing without needing a second machine or VM — see the "Second-instance Antiserum validation" note in `ROADMAP.md` for why this is sufficient. It sets every path/socket/port variable in this document explicitly, so it never collides with `launch_host_a.sh`. For any `HOST_NAME` other than `b` you must set `DENDRITE_HOST_HTTP_PORT` yourself (it covers both HTTP and the `/ws` WebSocket upgrade — see "WebSocket merged onto the HTTP port" in `ROADMAP.md`'s Batch 7), so that adding a third or fourth host is always an explicit, collision-free choice rather than a guess. It also supports `--cleanup` (delete that host's `data/` only) and `--remove-host` (delete that host's entire folder, for tearing one down completely). Run either script with `--help` for the full option list.