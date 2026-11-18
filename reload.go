package embedshim

import (
	"context"
	"io/ioutil"
	"path/filepath"
	"time"

	pkgbundle "github.com/fuweid/embedshim/pkg/bundle"
	"github.com/fuweid/embedshim/pkg/pidfd"

	"github.com/cilium/ebpf"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/pkg/stdio"
	"github.com/containerd/containerd/runtime"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// reloadExistingTasks rebuilds the in-memory task table after a restart.
//
// Phase 1 is record-based recovery: every task that persisted a record is
// classified (alive / exited / pid-reused / unfinished-create) and
// rebuilt, reconciled or cleaned accordingly. Phase 2 is the legacy
// fallback for bundles written before records existed.
func (manager *TaskManager) reloadExistingTasks(ctx context.Context) error {
	cleaner := newLeftoverCleaner(
		sysCleanerOps{procs: manager.procs},
		runcRoot,
		manager.rootDir,
		nil, // no fault hooks in production
	)
	rec := newRecoverer(
		manager.store,
		manager.procs,
		&managerRecoveryHandler{manager: manager},
		cleaner,
		manager.recovery,
		nil,
	)
	result, err := rec.Recover(ctx)
	if err != nil {
		return err
	}
	return manager.reloadLegacyTasks(ctx, result.Handled)
}

// reloadLegacyTasks reloads bundles that have no persisted task record
// (written by an embedshim version before persistence, or left behind by
// a crash between bundle creation and the first record write).
func (manager *TaskManager) reloadLegacyTasks(ctx context.Context, handled map[string]bool) error {
	nsDirs, err := ioutil.ReadDir(manager.stateDir)
	if err != nil {
		return err
	}

	for _, nsd := range nsDirs {
		if !nsd.IsDir() {
			continue
		}

		ns := nsd.Name()
		if len(ns) > 0 && ns[0] == '.' {
			continue
		}

		log.G(ctx).WithField("namespace", ns).Info("loading tasks in namespace")
		if err := manager.loadTasks(namespaces.WithNamespace(ctx, ns), handled); err != nil {
			log.G(ctx).WithField("namespace", ns).WithError(err).Error("loading tasks in namespace")
			continue
		}
	}
	return nil
}

func (manager *TaskManager) loadTasks(ctx context.Context, handled map[string]bool) error {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return err
	}

	shimDirs, err := ioutil.ReadDir(filepath.Join(manager.stateDir, ns))
	if err != nil {
		return err
	}

	for _, sd := range shimDirs {
		if !sd.IsDir() {
			continue
		}

		id := sd.Name()
		if len(id) > 0 && id[0] == '.' {
			continue
		}

		// Tasks with a persisted record were already recovered (or
		// deliberately quarantined) by the record-based pass.
		if handled[taskKey(ns, id)] {
			continue
		}

		bundle, err := pkgbundle.LoadBundle(manager.stateDir, ns, id)
		if err != nil {
			return err
		}

		// fast path
		if err := bundle.IsValid(); err != nil {
			log.G(ctx).WithError(err).Errorf("bundle %s is invalid, cleanup", bundle.Path)
			bundle.Delete()
			continue
		}

		shim, err := manager.loadShim(ctx, bundle)
		if err != nil {
			log.G(ctx).WithError(err).Errorf("failed to load exiting task %s", id)
			bundle.Delete()
			continue
		}

		if _, err := manager.containers.Get(ctx, id); err != nil {
			log.G(ctx).WithError(err).Errorf("failed to load container %s and start to delete task", id)
			shim.Delete(ctx)
			continue
		}
		manager.tasks.Add(ctx, shim)
	}
	return nil
}

func (manager *TaskManager) loadShim(ctx context.Context, bundle *pkgbundle.Bundle) (_ *shim, retErr error) {
	init, err := renewInitProcess(ctx, bundle)
	if err != nil {
		return nil, err
	}

	defer func() {
		if retErr != nil {
			deferCtx, deferCancel := deferContext()
			defer deferCancel()

			init.Delete(deferCtx)

			manager.cleanInitProcessTraceEvent(init)
		}
	}()

	if err := manager.repollingInitProcess(init); err != nil {
		return nil, err
	}
	return renewShim(manager, init), nil
}

func renewShim(manager *TaskManager, init *initProcess) *shim {
	s := &shim{
		manager: manager,
		bundle:  init.bundle,
		init:    init,

		execProcesses:   make(map[string]runtime.Process),
		reservedExecIDs: make(map[string]struct{}),
	}
	init.parent = s
	return s
}

func renewInitProcess(ctx context.Context, bundle *pkgbundle.Bundle) (*initProcess, error) {
	init, err := newInitProcess(bundle)
	if err != nil {
		return nil, err
	}
	if err = init.reload(ctx); err != nil {
		return nil, err
	}

	return init, nil
}

// renewInitProcessFromRecord rebuilds an init process from its persisted
// record instead of asking the OCI runtime for state.
func renewInitProcessFromRecord(bundle *pkgbundle.Bundle, rec *TaskRecord) (*initProcess, error) {
	p, err := newInitProcess(bundle)
	if err != nil {
		return nil, err
	}

	p.pid = rec.Pid
	switch rec.Phase {
	case taskPhaseRunning:
		p.initState = &runningState{p: p}
	case taskPhasePaused:
		p.initState = &pausedState{p: p}
	case taskPhaseStopped:
		p.initState = &stoppedState{p: p}
	default:
		p.initState = &createdState{p: p}
	}
	return p, nil
}

// managerRecoveryHandler is the production recoveryHandler. Both reattach
// and reconcile go through repollingInitProcess — the same exitsnoop +
// pidfd reconciliation used at runtime — so exit events observed while the
// host was down are replayed by one shared mechanism, not reimplemented.
type managerRecoveryHandler struct {
	manager *TaskManager
}

func (h *managerRecoveryHandler) ReattachInit(ctx context.Context, rec *TaskRecord) error {
	return h.recoverInit(ctx, rec)
}

func (h *managerRecoveryHandler) ReconcileInitExit(ctx context.Context, rec *TaskRecord) error {
	return h.recoverInit(ctx, rec)
}

func (h *managerRecoveryHandler) recoverInit(ctx context.Context, rec *TaskRecord) (retErr error) {
	ctx = namespaces.WithNamespace(ctx, rec.Namespace)
	manager := h.manager

	bundle, err := pkgbundle.LoadBundle(manager.stateDir, rec.Namespace, rec.ID)
	if err != nil {
		return err
	}

	// A stopped task whose bundle is already gone was deleted while the
	// host was down, between the bundle removal and the record removal.
	// Drop the record; there is nothing to rebuild.
	if err := bundle.IsValid(); err != nil && rec.Phase == taskPhaseStopped {
		return manager.store.DeleteTask(rec.Namespace, rec.ID)
	}

	init, err := renewInitProcessFromRecord(bundle, rec)
	if err != nil {
		return err
	}

	defer func() {
		if retErr != nil {
			deferCtx, deferCancel := deferContext()
			defer deferCancel()
			init.Delete(deferCtx)
			manager.cleanInitProcessTraceEvent(init)
		}
	}()

	if err := manager.repollingInitProcess(init); err != nil {
		return err
	}

	s := renewShim(manager, init)
	return manager.tasks.Add(ctx, s)
}

func (h *managerRecoveryHandler) ReattachExec(ctx context.Context, taskRec *TaskRecord, execRec *ExecRecord) error {
	manager := h.manager
	ctx = namespaces.WithNamespace(ctx, taskRec.Namespace)

	task, err := manager.tasks.Get(ctx, taskRec.ID)
	if err != nil {
		return err
	}
	s, ok := task.(*shim)
	if !ok {
		return errors.Errorf("task %s is not an embedshim task", taskRec.ID)
	}

	e := renewExecProcessFromRecord(s.init, execRec)

	fd, err := pidfd.Open(uint32(execRec.Pid), 0)
	if err != nil {
		// The process died between classification and reattach; fall
		// back to replaying its exit event.
		return h.reconcileExecExit(s, e)
	}

	// Verify the pid still belongs to this exec: the exitsnoop tracing
	// table maps it to the same trace ID. A mismatch means the pid was
	// reused and must not be associated with this exec.
	taskInfo, err := manager.monitor.execStore.GetTracingTask(uint32(execRec.Pid))
	if err != nil {
		unix.Close(int(fd))
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return h.reconcileExecExit(s, e)
		}
		return err
	}
	if taskInfo == nil || taskInfo.TraceID != execRec.TraceEventID {
		unix.Close(int(fd))
		return h.reconcileExecExit(s, e)
	}

	e.pidFD = fd
	if err := e.traceExit(manager.monitor, fd); err != nil {
		unix.Close(int(fd))
		return err
	}
	s.addExecProcess(e)
	return nil
}

func (h *managerRecoveryHandler) ReconcileExecExit(ctx context.Context, taskRec *TaskRecord, execRec *ExecRecord) error {
	manager := h.manager
	ctx = namespaces.WithNamespace(ctx, taskRec.Namespace)

	task, err := manager.tasks.Get(ctx, taskRec.ID)
	if err != nil {
		return err
	}
	s, ok := task.(*shim)
	if !ok {
		return errors.Errorf("task %s is not an embedshim task", taskRec.ID)
	}
	return h.reconcileExecExit(s, renewExecProcessFromRecord(s.init, execRec))
}

// reconcileExecExit replays the exec's exit event recorded by exitsnoop
// while the host was down — the same source the runtime pidfd callback
// uses.
func (h *managerRecoveryHandler) reconcileExecExit(s *shim, e *execProcess) error {
	execStore := h.manager.monitor.execStore

	status := unexpectedExitCode
	if event, err := execStore.GetExitedEvent(e.traceEventID); err == nil {
		status = int(event.ExitCode)
		execStore.DeleteExitedEvent(e.traceEventID)
	}
	e.SetExited(status)
	s.addExecProcess(e)
	return nil
}

// renewExecProcessFromRecord rebuilds an exec process object from its
// persisted record.
func renewExecProcessFromRecord(init *initProcess, rec *ExecRecord) *execProcess {
	e := &execProcess{
		parent:       init,
		id:           rec.ID,
		traceEventID: rec.TraceEventID,
		stdio: stdio.Stdio{
			Stdin:    rec.Stdio.Stdin,
			Stdout:   rec.Stdio.Stdout,
			Stderr:   rec.Stdio.Stderr,
			Terminal: rec.Stdio.Terminal,
		},
		waitBlock: make(chan struct{}),
	}
	e.pid.pid = rec.Pid
	switch rec.Phase {
	case execPhaseStopped:
		e.execState = &execStoppedState{p: e}
	case execPhaseRunning:
		e.execState = &execRunningState{p: e}
	default:
		e.execState = &execCreatedState{p: e}
	}
	return e
}

// saveTaskRecord persists the current phase of the init process. It is
// best-effort: callers log the error but never fail the user operation,
// because the legacy bundle-scan remains as a fallback.
func (manager *TaskManager) saveTaskRecord(init *initProcess, phase string) error {
	if manager.store == nil {
		return nil
	}

	var (
		ns = init.bundle.Namespace
		id = init.ID()
	)

	rec := &TaskRecord{
		ID:           id,
		Namespace:    ns,
		BundlePath:   init.bundle.Path,
		TraceEventID: init.traceEventID,
		Pid:          init.pid,
		Phase:        phase,
		Stdio: stdioRecord{
			Stdin:    init.stdio.Stdin,
			Stdout:   init.stdio.Stdout,
			Stderr:   init.stdio.Stderr,
			Terminal: init.stdio.Terminal,
		},
	}

	// Preserve fields that only earlier versions of the record know.
	if old, err := manager.store.LoadTask(ns, id); err == nil {
		rec.CreatedAt = old.CreatedAt
		rec.PidStartTime = old.PidStartTime
		rec.CgroupPaths = old.CgroupPaths
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	if rec.Pid > 0 && rec.PidStartTime == 0 {
		if st, err := manager.procs.StartTime(rec.Pid); err == nil {
			rec.PidStartTime = st
		}
	}
	return manager.store.SaveTask(rec)
}

// saveExecRecord persists the current phase of an exec process.
func (manager *TaskManager) saveExecRecord(e *execProcess, phase string) error {
	if manager.store == nil {
		return nil
	}

	var (
		ns     = e.parent.bundle.Namespace
		taskID = e.parent.ID()
	)

	rec := &ExecRecord{
		ID:           e.id,
		TaskID:       taskID,
		TraceEventID: e.traceEventID,
		Pid:          e.pid.get(),
		Phase:        phase,
		Stdio: stdioRecord{
			Stdin:    e.stdio.Stdin,
			Stdout:   e.stdio.Stdout,
			Stderr:   e.stdio.Stderr,
			Terminal: e.stdio.Terminal,
		},
	}

	if old, err := loadExecRecord(manager.store, ns, taskID, e.id); err == nil {
		rec.CreatedAt = old.CreatedAt
		rec.PidStartTime = old.PidStartTime
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	if rec.Pid > 0 && rec.PidStartTime == 0 {
		if st, err := manager.procs.StartTime(rec.Pid); err == nil {
			rec.PidStartTime = st
		}
	}
	return manager.store.SaveExec(ns, taskID, rec)
}

func loadExecRecord(store taskStateStore, ns, taskID, execID string) (*ExecRecord, error) {
	execs, _, err := store.LoadExecs(ns, taskID)
	if err != nil {
		return nil, err
	}
	for _, e := range execs {
		if e.ID == execID {
			return e, nil
		}
	}
	return nil, errors.Errorf("exec record %s not found", execID)
}
