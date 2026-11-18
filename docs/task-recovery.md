# Task Recovery After Host Restart

embedshim runs inside the containerd process and keeps no daemon of its
own. When the host process restarts, the containers it managed may still
be running, but the in-memory task table and the exec (attached process)
table are gone. This document describes how the tables are rebuilt from
persisted state, how leftovers are cleaned, and how the design is tested
against crashes at every step.

## What is persisted

Every task writes a record at
`<stateDir>/<namespace>/<id>/task.json` (`TaskRecord`):

| field | purpose |
|---|---|
| `version` | on-disk layout version, drives migration |
| `id`, `namespace` | task identity |
| `bundlePath` | the OCI bundle (state) directory |
| `traceEventID` | key into the exitsnoop reconciliation maps |
| `pid`, `pidStartTime` | init process identity; the start time (`/proc/<pid>/stat` field 22) disambiguates a reused pid |
| `phase` | `creating` / `created` / `running` / `paused` / `stopped` |
| `createdAt` | task creation time |
| `stdio` | stdin/stdout/stderr paths and the terminal flag |
| `cgroupPaths` | best-effort cleanup hints |

Each exec process writes `<stateDir>/<namespace>/<id>/exec.<execID>.json`
(`ExecRecord`) with the same identity fields (pid, pidStartTime, phase,
traceEventID, stdio).

Records are written **before** the operation they describe: the
`creating` record is written before the OCI runtime is invoked, and
phase updates follow each successful transition (`created`, `running`,
`paused`, exec create/start). Exit itself is *not* persisted — a dead
process is cheaper to rediscover through reconciliation than to
persist synchronously on the hot path.

## Write path

Writes go to `<name>.tmp-<pid>` in the same directory, are fsynced,
atomically renamed over the target, and the directory is fsynced. A host
crash therefore leaves either the previous complete record or a
`*.tmp-*` leftover — never a truncated `task.json`. Recovery ignores
`*.tmp-*` files.

## Corruption and versioning

A record that fails to decode, carries an unknown (newer) version, or
fails migration is a `StateError` with one of three kinds: `corrupt`,
`unknown-version`, `migration-failed`. The policy for all three:

1. the task is marked **unrecoverable** and an error is logged (alert);
2. the file is **quarantined** — renamed to `<name>.corrupt`, never
   deleted, so an operator can still inspect or repair it;
3. recovery of every other task proceeds.

The version field allows forward migration: a new binary reads old
records by stepping them through `migrateTaskRecord` (v0 → v1 exists
today; v0 lacked `pidStartTime`, so migrated records carry a zero start
time and the recoverer falls back to the shared identity checks instead
of trusting the pid). A record from a *newer* binary is not read at all
— it is quarantined as `unknown-version`. A failed migration is treated
exactly like corruption: quarantine, alert, keep the data.

## Recovery classification

For each persisted record the recoverer resolves the process identity
through an injectable `processInspector`:

* **alive** — pid exists and `pidStartTime` matches: rebuild the task
  and re-arm exit watching.
* **gone** — pid no longer exists: the exit event is replayed through
  the *same* exitsnoop + pidfd reconciliation used at runtime
  (`monitor.repollingInitProcess` / the exec exit store). No second
  exit-discovery mechanism is implemented for recovery.
* **pid reused** — pid exists but the start time differs: the record
  belongs to a dead process instance. It is reconciled as exited and is
  **never** associated with the new process. (A zero `pidStartTime`
  from a migrated record takes the conservative path: the shared
  mechanism re-verifies the identity via the runc-init `exec.fifo`
  check before trusting the pid.)

Exec records of a recovered task are classified the same way; execs of
an exited task are reconciled without further checks.

A record still in `creating` phase describes a task whose init process
never provably started — a crash during `Create`. It is **cleaned, not
recovered**: rootfs mounts, the runc state dir (including the temporary
`exec.fifo`), the work dir, empty cgroup dirs and the bundle itself are
removed.

## Cleanup preconditions and idempotency

Cleanup is destructive, so it is guarded:

* only resources of records in `creating` phase (or otherwise confirmed
  terminal) are candidates;
* a bundle path referenced by **any other record** is refused — the
  task is marked unrecoverable instead of deleting shared state;
* a cgroup is removed only when `cgroup.procs` contains no living
  process;
* unmounts are lazy and scoped to the task's own rootfs, so mounts
  still used by other containers are untouched.

Every cleanup step tolerates already-removed resources, and the bundle
(which contains the record) is removed **last**. A crash anywhere in
cleanup leaves the record in place, and the next recovery simply
re-runs the same steps to the same fixed point.

## Recovery vs. new requests

Two options were considered: block all requests until recovery
completes, or expose partially recovered state. The design exposes
partial state with deterministic answers:

* tasks already recovered are served normally;
* a task known to be persisted but not yet recovered answers
  `unavailable` ("still being recovered") — **not** `not found`;
* a task whose record was quarantined answers "cannot be recovered"
  with the cause.

This is implemented by the `recoveryRegistry` and enforced in
`TaskManager.Get`. Reporting `not found` for a task that is in fact
alive would invite clients to recreate it under the same id, so a
misleading `not found` is considered worse than a temporary
`unavailable`. Recovery currently runs synchronously during plugin
initialization (preserving the previous behavior), but the registry
makes the semantics correct if recovery is moved to a background
pass.

## Crash-point testing

Persistence (`taskStateStore`), the process table (`processInspector`),
the task/exec table (`recoveryHandler`) and cleanup (`cleanerOps`) are
all injectable. Every step boundary of persistence, recovery and
cleanup is a named fault-injection point (`faultHooks`), nil in
production.

A simulated crash panics at the configured point; the test then drops
**every** in-memory object and rebuilds the recoverer, handler and
registry over the *same* state directory — exactly what a host restart
sees — and asserts the final state (recovery actions and full disk
contents) is identical to a crash-free run. Covered scenarios:

* interrupted write leaving a `*.tmp-*` file;
* corrupted task record (quarantine, data kept, others recover);
* unknown-version record and failed v0→v1 migration;
* process alive / gone / pid reused;
* unfinished `creating` task (mounts, runc state, cgroup, bundle);
* exec table recovery (alive exec reattached, dead exec reconciled);
* crash at every recovery and cleanup step, including repeated crashes
  during cleanup.
