/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package embedshim

import (
	"context"
	"fmt"
	"sync"

	"github.com/containerd/containerd/log"
)

// Fault-injection point names used by the recoverer.
const (
	faultRecoverListed         = "recover.listed"
	faultRecoverTaskClassified = "recover.task.classified"
	faultRecoverInitDone       = "recover.init.done"
	faultRecoverExecsDone      = "recover.execs.done"
	faultRecoverTaskDone       = "recover.task.done"
)

// recoveryHandler performs the mechanism side of recovery. The recoverer
// decides *what* each record is (alive, gone, pid-reused, unfinished); the
// handler rebuilds the in-memory objects. Both Reattach and ReconcileExit
// implementations must go through the same exit-event reconciliation
// mechanism used at runtime (exitsnoop + pidfd polling), never a
// reimplementation of it.
type recoveryHandler interface {
	// ReattachInit rebuilds the in-memory task for a process that is
	// still alive and re-arms exit watching.
	ReattachInit(ctx context.Context, rec *TaskRecord) error
	// ReconcileInitExit rebuilds the in-memory task for a process that is
	// gone (or whose pid was reused) and replays its exit event through
	// the shared reconciliation mechanism.
	ReconcileInitExit(ctx context.Context, rec *TaskRecord) error
	// ReattachExec rebuilds an attached (exec) process that is still
	// alive and re-arms exit watching.
	ReattachExec(ctx context.Context, task *TaskRecord, exec *ExecRecord) error
	// ReconcileExecExit replays the exit of an attached process through
	// the shared reconciliation mechanism.
	ReconcileExecExit(ctx context.Context, task *TaskRecord, exec *ExecRecord) error
}

// recoveryAction is the recoverer's classification of one record.
type recoveryAction int

const (
	actionReattach recoveryAction = iota
	actionReconcileExit
)

// RecoveryResult summarizes one recovery pass. Handled contains every
// task key (namespace/id) the recoverer took responsibility for, so the
// legacy bundle-scan fallback skips them.
type RecoveryResult struct {
	Reattached    []string
	Reconciled    []string
	Cleaned       []string
	Unrecoverable map[string]error
	Handled       map[string]bool
}

func taskKey(ns, id string) string { return ns + "/" + id }

// recoverer rebuilds the task table from persisted records after a host
// restart. All of its dependencies (store, process table, handler,
// cleaner) are injectable, and every step boundary is a fault-injection
// point, so tests can simulate a crash between any two steps by dropping
// the recoverer and re-creating it over the same state directory.
type recoverer struct {
	store   taskStateStore
	procs   processInspector
	handler recoveryHandler
	cleaner *leftoverCleaner
	hooks   faultHooks

	// registry tracks per-task recovery progress so that queries made
	// while recovery is in flight get a deterministic answer.
	registry *recoveryRegistry
}

func newRecoverer(store taskStateStore, procs processInspector, handler recoveryHandler,
	cleaner *leftoverCleaner, registry *recoveryRegistry, hooks faultHooks) *recoverer {
	if registry == nil {
		registry = newRecoveryRegistry()
	}
	return &recoverer{
		store:    store,
		procs:    procs,
		handler:  handler,
		cleaner:  cleaner,
		hooks:    hooks,
		registry: registry,
	}
}

// Recover runs one full recovery pass. It never fails because of a single
// bad record: unrecoverable records are quarantined, alerted on, and
// reported in the result.
func (r *recoverer) Recover(ctx context.Context) (*RecoveryResult, error) {
	lg := log.G(ctx)
	result := &RecoveryResult{
		Unrecoverable: make(map[string]error),
		Handled:       make(map[string]bool),
	}

	listed, err := r.store.ListTasks()
	if err != nil {
		return nil, fmt.Errorf("failed to list persisted task records: %w", err)
	}

	// Quarantined records: alert, mark the task unrecoverable, keep going.
	// The task is registered as failed so queries report "unrecoverable"
	// instead of "not found", and marked handled so the legacy bundle
	// scan does not resurrect a record we deliberately set aside.
	for _, u := range listed.Unrecoverable {
		lg.WithError(u.Err).Errorf("recovery: task record %s is unrecoverable, quarantined", u.Path)
		key := taskKey(u.Namespace, u.ID)
		result.Unrecoverable[key] = u.Err
		result.Handled[key] = true
		r.registry.fail(key, u.Err)
	}

	// Register every task up front so concurrent queries can distinguish
	// "recovering" from "not found".
	pending := make([]string, 0, len(listed.Tasks))
	for _, rec := range listed.Tasks {
		pending = append(pending, taskKey(rec.Namespace, rec.ID))
	}
	r.registry.begin(pending)
	hitFault(r.hooks, faultRecoverListed)

	for _, rec := range listed.Tasks {
		key := taskKey(rec.Namespace, rec.ID)
		result.Handled[key] = true
		r.recoverTask(ctx, rec, listed.Tasks, result)
	}
	return result, nil
}

func (r *recoverer) recoverTask(ctx context.Context, rec *TaskRecord, all []*TaskRecord, result *RecoveryResult) {
	key := taskKey(rec.Namespace, rec.ID)
	lg := log.G(ctx).WithField("task", rec.ID).WithField("namespace", rec.Namespace)

	fail := func(err error) {
		lg.WithError(err).Error("recovery: task is unrecoverable")
		result.Unrecoverable[key] = err
		r.registry.fail(key, err)
	}

	// Records left in the creating phase describe a task whose init
	// process never (provably) started: leftovers of a host crash during
	// Create. They are cleaned, not recovered.
	if rec.Phase == taskPhaseCreating {
		if bundleReferencedByOthers(rec, all) {
			fail(fmt.Errorf("bundle %s is still referenced by another task, refusing to clean", rec.BundlePath))
			return
		}
		if err := r.cleaner.Clean(ctx, rec); err != nil {
			fail(fmt.Errorf("failed to clean unfinished task: %w", err))
			return
		}
		// The record lived inside the bundle and is gone with it; make
		// sure even for stores that keep records elsewhere.
		if err := r.store.DeleteTask(rec.Namespace, rec.ID); err != nil {
			lg.WithError(err).Warn("recovery: failed to remove record of cleaned task")
		}
		result.Cleaned = append(result.Cleaned, key)
		r.registry.done(key)
		return
	}

	hitFault(r.hooks, faultRecoverTaskClassified)

	switch r.classify(rec.Pid, rec.PidStartTime) {
	case actionReattach:
		if err := r.handler.ReattachInit(ctx, rec); err != nil {
			fail(fmt.Errorf("failed to reattach init process: %w", err))
			return
		}
		result.Reattached = append(result.Reattached, key)
	case actionReconcileExit:
		if err := r.handler.ReconcileInitExit(ctx, rec); err != nil {
			fail(fmt.Errorf("failed to reconcile exited init process: %w", err))
			return
		}
		result.Reconciled = append(result.Reconciled, key)
	}
	hitFault(r.hooks, faultRecoverInitDone)

	r.recoverExecs(ctx, rec, result, fail)
	hitFault(r.hooks, faultRecoverExecsDone)

	result.Handled[key] = true
	r.registry.done(key)
	hitFault(r.hooks, faultRecoverTaskDone)
}

// classify decides whether the persisted process identity is still the
// same live process instance.
//
//   - pid gone: the process exited while the host was down; its exit event
//     is replayed through the shared reconciliation mechanism.
//   - pid alive but start-time mismatch: the pid was reused by an
//     unrelated process. The record must be treated as exited and must
//     never be associated with the new process.
//   - pid alive and start-time match: same instance, reattach.
//   - start-time unknown (migrated record): conservatively reattach; the
//     shared reconciliation mechanism re-verifies the identity (runc-init
//     exec.fifo check) before trusting the pid.
func (r *recoverer) classify(pid int, pidStartTime uint64) recoveryAction {
	if pid <= 0 {
		return actionReconcileExit
	}
	startTime, err := r.procs.StartTime(pid)
	if err != nil {
		// errProcessNotExist and any /proc read failure both land here:
		// an unreadable /proc entry means we cannot prove the process is
		// ours, and reconciliation is always the safe direction.
		return actionReconcileExit
	}
	if pidStartTime != 0 && startTime != pidStartTime {
		return actionReconcileExit
	}
	return actionReattach
}

// recoverExecs restores the attached-process table of one task.
func (r *recoverer) recoverExecs(ctx context.Context, rec *TaskRecord, result *RecoveryResult, fail func(error)) {
	execs, unrecoverable, err := r.store.LoadExecs(rec.Namespace, rec.ID)
	if err != nil {
		fail(fmt.Errorf("failed to load exec records: %w", err))
		return
	}
	for _, u := range unrecoverable {
		log.G(ctx).WithError(u.Err).Errorf("recovery: exec record %s is unrecoverable, quarantined", u.Path)
	}

	initAlive := r.classify(rec.Pid, rec.PidStartTime) == actionReattach
	for _, execRec := range execs {
		action := actionReconcileExit
		if initAlive && execRec.Phase != execPhaseStopped {
			action = r.classify(execRec.Pid, execRec.PidStartTime)
		}

		var err error
		if action == actionReattach {
			err = r.handler.ReattachExec(ctx, rec, execRec)
		} else {
			err = r.handler.ReconcileExecExit(ctx, rec, execRec)
		}
		if err != nil {
			fail(fmt.Errorf("failed to recover exec %s: %w", execRec.ID, err))
			return
		}
	}
}

// recoveryRegistry tracks which tasks are still being recovered. It lets
// the task manager answer queries during recovery with "recovering"
// instead of a misleading "not found", and it permanently records tasks
// that proved unrecoverable.
type recoveryRegistry struct {
	mu      sync.Mutex
	pending map[string]struct{}
	failed  map[string]error
}

func newRecoveryRegistry() *recoveryRegistry {
	return &recoveryRegistry{
		pending: make(map[string]struct{}),
		failed:  make(map[string]error),
	}
}

func (r *recoveryRegistry) begin(keys []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range keys {
		r.pending[k] = struct{}{}
	}
}

func (r *recoveryRegistry) done(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, key)
}

func (r *recoveryRegistry) fail(key string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, key)
	r.failed[key] = err
}

// isPending reports whether the task is known but not yet recovered.
func (r *recoveryRegistry) isPending(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.pending[key]
	return ok
}

// unrecoverableErr returns why the task can never be recovered, or nil.
func (r *recoveryRegistry) unrecoverableErr(key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed[key]
}
