# TODO

Running list of small items found while working through the codebase. This is
a scratch tracking file, not a design document or a historical log — each
item should end up either fixed, folded into `ROADMAP.md`/`architecture.md`/
other docs, or explicitly dropped, and then removed from this list once it's
captured wherever it actually belongs. Nothing here should stay open
indefinitely without a reason.

## Open

- [x] Re-test the hub-node relationship cap
  (`PathQuery::max_relationships_per_node`, `MAX_RELATIONSHIPS_PER_NODE_FOR_REASONING`
  in `core.rs`) against a live full-load run on real hardware (FileFlows/ffmpeg
  transcode running, same `host:local`-hub scenario). **Confirmed fixed**:
  routine's `processed`/`queue wait`/`processing` counters advance steadily
  across checks (no more zero-progress freeze), where the pre-fix run showed
  those counters completely frozen for minutes while the queue climbed. `200`
  (`MAX_RELATIONSHIPS_PER_NODE_FOR_REASONING`) is still a reasoned-but-unbenchmarked
  choice — revisit if a real hub node's fan-out ever approaches it, but the
  hang itself is resolved.

- [ ] Routine-lane throughput ceiling under heavy contention. Same live
  re-test (hub-node stall now fixed, see above) still shows the queue growing
  steadily (1,502 → 1,960 → 2,191 → 2,750 across four checks, wait times
  climbing past 20s) with `dendrited` steady at 100% CPU while sharing a core
  with `ffmpeg` at ~287%. This is not a stall — every check shows real
  progress — it's the already-documented Batch 10 finding (`ROADMAP.md`, the
  92.3%-CPU case): genuine sustained per-item cost times genuine sustained
  arrival rate, on weak hardware sharing a core with another CPU-bound
  workload. Confirmed non-monotonic, not a one-way backlog: the queue is
  observed to drain some when the competing CPU-bound job's load eases up
  momentarily, then grow again when it doesn't — consistent with two
  workloads genuinely trading time on one core, not a fixed processing
  ceiling Dendrite can never clear on its own. Separate, lower-urgency
  question from the hang above: whether routine's per-item cost or batch
  sizing should be tightened further so it holds up better under sustained
  contention, or whether this variability is simply the expected behaviour
  for this hardware and should be left as-is.

- [ ] Exercise the merged HTTP/WebSocket port (`docs/ROADMAP.md`'s Batch 7
  distribution-packaging note: `DENDRITE_WS_ADDR` removed, `/ws` now upgrades
  on the same `DENDRITE_HTTP_ADDR` listener) through the actual UI rather
  than a raw socket. A manual handshake script confirmed the daemon itself
  serves both protocols correctly on one port (real `101 Switching Protocols`
  + a live `pipeline` event frame received over that connection), but the
  UI's Live Event Stream / Dashboard pages haven't yet been pointed at a
  running `dendrited` through this path — worth doing once `npm run dev`
  (proxying `/ws` to the merged port per the updated `vite.config.ts`) or a
  built `ui/dist` served by `dendrited` itself is available to test against.
  A built `ui/dist` served by `dendrited` (`DENDRITE_UI_DIR`) is now
  available — this is otherwise unblocked.

- [ ] Set a real `maintainer` contact in `crates/dendrited/Cargo.toml`'s
  `[package.metadata.deb]` before actually distributing the `.deb` — it's
  currently the placeholder `Anthrosystems <packaging@anthrosys.example>`.

- [ ] Run `scripts/build-deb.sh` somewhere with a real `bpf-linker`/nightly
  toolchain and confirm the resulting `.deb` installs and starts correctly
  end to end on an actual systemd host. Everything except the eBPF object
  itself has been verified in this sandbox (a real `npm run build` UI, a
  real `dpkg -i`/`-r`/`-P` lifecycle test of user/group creation, file
  placement, the conffile, and remove-vs-purge state handling) — only the
  eBPF asset was a stub file (no toolchain available here), and only the
  actual `systemctl enable --now` step was untested (this sandbox has no
  systemd as PID 1 to hand it to, so those calls no-op via their own
  `[ -d /run/systemd/system ]` guards rather than actually running).
