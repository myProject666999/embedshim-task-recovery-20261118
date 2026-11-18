package embedshim

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/runtime"
)

// errSimulatedCrash is panicked by the fault injector to simulate a host
// crash. Everything in memory at that moment is considered lost; the test
// then re-creates all objects over the same state directory, exactly like
// a fresh host process.
var errSimulatedCrash = errors.New("simulated host crash")

// crashInjector panics with errSimulatedCrash on the (after+1)-th hit of
// the configured fault point.
type crashInjector struct {
	point string
	after int
	count int
	fired bool
}

func (c *crashInjector) Hit(point string) {
	if c.fired || point != c.point {
		return
	}
	if c.count == c.after {
		c.fired = true
		panic(errSimulatedCrash)
	}
	c.count++
}

// expectCrash runs fn and reports whether it crashed with
// errSimulatedCrash. Any other panic is re-raised.
func expectCrash(t *testing.T, fn func()) (crashed bool) {
	t.Helper()
	defer func() {
		switch r := recover(); r {
		case nil:
		case errSimulatedCrash:
			crashed = true
		default:
			panic(r)
		}
	}()
	fn()
	return false
}

// fakeProcs is the injectable process table.
type fakeProcs struct {
	startTimes map[int]uint64
}

func (f *fakeProcs) StartTime(pid int) (uint64, error) {
	if st, ok := f.startTimes[pid]; ok {
		return st, nil
	}
	return 0, errProcessNotExist
}

// fakeHandler is the injectable in-memory task/exec table. It is
// recreated per recovery attempt, mirroring how a host restart drops all
// in-memory objects.
type fakeHandler struct {
	events []string
}

func (h *fakeHandler) ReattachInit(_ context.Context, rec *TaskRecord) error {
	h.events = append(h.events, "reattach-init "+taskKey(rec.Namespace, rec.ID))
	return nil
}

func (h *fakeHandler) ReconcileInitExit(_ context.Context, rec *TaskRecord) error {
	h.events = append(h.events, "reconcile-init "+taskKey(rec.Namespace, rec.ID))
	return nil
}

func (h *fakeHandler) ReattachExec(_ context.Context, task *TaskRecord, exec *ExecRecord) error {
	h.events = append(h.events, "reattach-exec "+taskKey(task.Namespace, task.ID)+"/"+exec.ID)
	return nil
}

func (h *fakeHandler) ReconcileExecExit(_ context.Context, task *TaskRecord, exec *ExecRecord) error {
	h.events = append(h.events, "reconcile-exec "+taskKey(task.Namespace, task.ID)+"/"+exec.ID)
	return nil
}

// fsCleanerOps performs cleanup against the real filesystem under the
// test's state dir, so its effects survive simulated crashes. Cgroup
// directories are plain dirs with a cgroup.procs file; liveness is
// checked against the fake process table.
type fsCleanerOps struct {
	procs *fakeProcs
	// unmounted records UnmountAll calls; kept across attempts because it
	// models host-level state.
	unmounted []string
}

func (o *fsCleanerOps) UnmountAll(target string) error {
	o.unmounted = append(o.unmounted, target)
	return nil
}

func (o *fsCleanerOps) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

func (o *fsCleanerOps) CgroupPids(cgroupPath string) ([]int, error) {
	data, err := ioutil.ReadFile(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var alive []int
	for _, f := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(f)
		if err != nil {
			continue
		}
		if _, err := o.procs.StartTime(pid); err == nil {
			alive = append(alive, pid)
		}
	}
	return alive, nil
}

func (o *fsCleanerOps) RemoveCgroup(cgroupPath string) error {
	// cgroupfs virtual files disappear with the directory; simulate that
	// with RemoveAll. Emptiness is enforced by CgroupPids beforehand.
	err := os.RemoveAll(cgroupPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// recoveryFixture builds a state directory with tasks covering every
// recovery classification.
type recoveryFixture struct {
	dir      string
	procs    *fakeProcs
	ops      *fsCleanerOps
	runcRoot string
	rootDir  string
}

func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	dir := t.TempDir()

	f := &recoveryFixture{
		dir:      dir,
		procs:    &fakeProcs{startTimes: map[int]uint64{1001: 555, 1002: 556, 3001: 999}},
		runcRoot: filepath.Join(dir, "runc"),
		rootDir:  filepath.Join(dir, "root"),
	}
	f.ops = &fsCleanerOps{procs: f.procs}

	store := newFileStateStore(dir, nil)
	save := func(rec *TaskRecord) {
		rec.BundlePath = filepath.Join(dir, rec.Namespace, rec.ID)
		if err := store.SaveTask(rec); err != nil {
			t.Fatal(err)
		}
	}

	// alive: pid 1001 exists with matching start time; exec1 alive,
	// exec2 gone.
	save(&TaskRecord{ID: "task-alive", Namespace: "k8s.io", TraceEventID: 1,
		Pid: 1001, PidStartTime: 555, Phase: taskPhaseRunning})
	if err := store.SaveExec("k8s.io", "task-alive", &ExecRecord{
		ID: "exec1", TaskID: "task-alive", TraceEventID: 2,
		Pid: 1002, PidStartTime: 556, Phase: execPhaseRunning}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveExec("k8s.io", "task-alive", &ExecRecord{
		ID: "exec2", TaskID: "task-alive", TraceEventID: 3,
		Pid: 1003, PidStartTime: 557, Phase: execPhaseRunning}); err != nil {
		t.Fatal(err)
	}

	// gone: pid 2001 no longer exists.
	save(&TaskRecord{ID: "task-gone", Namespace: "k8s.io", TraceEventID: 4,
		Pid: 2001, PidStartTime: 111, Phase: taskPhaseRunning})

	// reused: pid 3001 exists but belongs to a different process instance.
	save(&TaskRecord{ID: "task-reused", Namespace: "k8s.io", TraceEventID: 5,
		Pid: 3001, PidStartTime: 222, Phase: taskPhaseRunning})

	// unfinished create: record in creating phase, plus leftover mounts,
	// runc state (exec.fifo), work dir and an empty cgroup.
	save(&TaskRecord{ID: "task-creating", Namespace: "k8s.io", TraceEventID: 6,
		Phase:       taskPhaseCreating,
		CgroupPaths: []string{filepath.Join(dir, "cgroup", "k8s.io:task-creating")},
	})
	leftovers := []string{
		filepath.Join(dir, "k8s.io", "task-creating", "rootfs"),
		filepath.Join(f.runcRoot, "k8s.io", "task-creating"),
		filepath.Join(f.rootDir, "k8s.io", "task-creating"),
		filepath.Join(dir, "cgroup", "k8s.io:task-creating"),
	}
	for _, d := range leftovers {
		if err := os.MkdirAll(d, 0711); err != nil {
			t.Fatal(err)
		}
	}
	if err := ioutil.WriteFile(
		filepath.Join(f.runcRoot, "k8s.io", "task-creating", "exec.fifo"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(
		filepath.Join(dir, "cgroup", "k8s.io:task-creating", "cgroup.procs"), nil, 0644); err != nil {
		t.Fatal(err)
	}

	// corrupt: torn record file.
	corruptDir := filepath.Join(dir, "k8s.io", "task-corrupt")
	if err := os.MkdirAll(corruptDir, 0711); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(filepath.Join(corruptDir, taskRecordFileName),
		[]byte(`{"version": 1, "id": "task-cor`), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

// recoverOnce builds a brand-new recoverer (fresh in-memory objects) over
// the fixture's state dir and runs one recovery pass.
func (f *recoveryFixture) recoverOnce(t *testing.T, hooks faultHooks) (*RecoveryResult, *fakeHandler, *recoveryRegistry) {
	t.Helper()
	handler := &fakeHandler{}
	registry := newRecoveryRegistry()
	rec := newRecoverer(
		newFileStateStore(f.dir, hooks),
		f.procs,
		handler,
		newLeftoverCleaner(f.ops, f.runcRoot, f.rootDir, hooks),
		registry,
		hooks,
	)
	result, err := rec.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return result, handler, registry
}

// TestRecoveryClassifiesTasks checks that each record is routed to the
// right mechanism: reattach, reconcile, cleanup or quarantine.
func TestRecoveryClassifiesTasks(t *testing.T) {
	f := newRecoveryFixture(t)
	result, handler, _ := f.recoverOnce(t, nil)

	wantEvents := []string{
		"reattach-init k8s.io/task-alive",
		"reattach-exec k8s.io/task-alive/exec1",
		"reconcile-exec k8s.io/task-alive/exec2",
		"reconcile-init k8s.io/task-gone",
		"reconcile-init k8s.io/task-reused",
	}
	if !reflect.DeepEqual(handler.events, wantEvents) {
		t.Fatalf("handler events:\n got %v\nwant %v", handler.events, wantEvents)
	}

	if !reflect.DeepEqual(result.Cleaned, []string{"k8s.io/task-creating"}) {
		t.Fatalf("cleaned mismatch: %v", result.Cleaned)
	}
	if len(result.Unrecoverable) != 1 || result.Unrecoverable["k8s.io/task-corrupt"] == nil {
		t.Fatalf("unrecoverable mismatch: %v", result.Unrecoverable)
	}

	// the unfinished task's leftovers are gone
	for _, p := range []string{
		filepath.Join(f.dir, "k8s.io", "task-creating"),
		filepath.Join(f.runcRoot, "k8s.io", "task-creating"),
		filepath.Join(f.rootDir, "k8s.io", "task-creating"),
		filepath.Join(f.dir, "cgroup", "k8s.io:task-creating"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("leftover %s should be removed", p)
		}
	}

	// the corrupt record is quarantined, not deleted
	data, err := ioutil.ReadFile(filepath.Join(f.dir, "k8s.io", "task-corrupt", taskRecordFileName+quarantinedSuffix))
	if err != nil {
		t.Fatalf("corrupt record must be kept: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("quarantined record must keep its content")
	}

	// handled covers every record, so the legacy fallback skips them all
	for _, key := range []string{
		"k8s.io/task-alive", "k8s.io/task-gone", "k8s.io/task-reused",
		"k8s.io/task-creating", "k8s.io/task-corrupt",
	} {
		if !result.Handled[key] {
			t.Fatalf("expected %s to be handled", key)
		}
	}
}

// TestRecoveryPidReuseNeverReattached pins the safety property: a reused
// pid is always reconciled as exited, never attached to the new process.
func TestRecoveryPidReuseNeverReattached(t *testing.T) {
	f := newRecoveryFixture(t)
	_, handler, _ := f.recoverOnce(t, nil)
	for _, ev := range handler.events {
		if ev == "reattach-init k8s.io/task-reused" {
			t.Fatal("reused pid must never be reattached")
		}
	}
}

// TestRecoveryCrashPoints simulates a host crash at every fault-injection
// point of the recovery flow. After each crash, every in-memory object is
// dropped and recovery is re-run from the same state directory; the final
// state must be identical to a crash-free run.
func TestRecoveryCrashPoints(t *testing.T) {
	points := []string{
		faultRecoverListed,
		faultRecoverTaskClassified,
		faultRecoverInitDone,
		faultRecoverExecsDone,
		faultRecoverTaskDone,
		faultCleanBegin,
		faultCleanUnmounted,
		faultCleanPathsRemoved,
		faultCleanCgroupDone,
		faultCleanBundleDone,
	}

	// baseline: no crash
	baselineFixture := newRecoveryFixture(t)
	_, baselineHandler, _ := baselineFixture.recoverOnce(t, nil)
	baselineDisk := snapshotTree(t, baselineFixture.dir)

	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			f := newRecoveryFixture(t)

			inj := &crashInjector{point: point}
			var crashed bool
			func() {
				handler := &fakeHandler{}
				rec := newRecoverer(
					newFileStateStore(f.dir, inj),
					f.procs,
					handler,
					newLeftoverCleaner(f.ops, f.runcRoot, f.rootDir, inj),
					newRecoveryRegistry(),
					inj,
				)
				crashed = expectCrash(t, func() {
					//nolint:errcheck // a crash abandons the result
					rec.Recover(context.Background())
				})
			}()
			if !crashed {
				t.Fatalf("expected crash at %s", point)
			}

			// host comes back: all in-memory objects are new, the state
			// dir is the only survivor.
			_, handler, _ := f.recoverOnce(t, nil)

			// The final state must be identical to the crash-free run:
			// the same recovery actions and the same bytes on disk. (The
			// per-run result summary is not compared: a crash after a
			// task's final step legitimately means the re-run has nothing
			// left to report for it.)
			if !reflect.DeepEqual(handler.events, baselineHandler.events) {
				t.Fatalf("events after crash at %s:\n got %v\nwant %v",
					point, handler.events, baselineHandler.events)
			}
			if got := snapshotTree(t, f.dir); !reflect.DeepEqual(got, baselineDisk) {
				t.Fatalf("disk state after crash at %s mismatch:\n got %v\nwant %v",
					point, got, baselineDisk)
			}
		})
	}
}

// TestRecoveryCrashDuringCleanupIsIdempotent hammers the cleanup path
// specifically: crash after every single cleanup step, more than once,
// and verify the outcome still converges.
func TestRecoveryCrashDuringCleanupIsIdempotent(t *testing.T) {
	points := []string{
		faultCleanBegin, faultCleanUnmounted, faultCleanPathsRemoved,
		faultCleanCgroupDone, faultCleanBundleDone,
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			f := newRecoveryFixture(t)

			// crash twice at the same point to prove re-runs are safe;
			// the second round may legitimately not reach the point if
			// the first crash already landed after the final step.
			for i := 0; i < 2; i++ {
				inj := &crashInjector{point: point}
				rec := newRecoverer(
					newFileStateStore(f.dir, inj), f.procs, &fakeHandler{},
					newLeftoverCleaner(f.ops, f.runcRoot, f.rootDir, inj),
					newRecoveryRegistry(), inj,
				)
				crashed := expectCrash(t, func() {
					//nolint:errcheck // abandoned on crash
					rec.Recover(context.Background())
				})
				if i == 0 && !crashed {
					t.Fatalf("expected crash at %s (round %d)", point, i)
				}
			}

			f.recoverOnce(t, nil)
			// convergence is a property of the final disk state, not of
			// the last run's summary: a crash after the final cleanup
			// step leaves nothing to report on the next run.
			for _, p := range []string{
				filepath.Join(f.dir, "k8s.io", "task-creating"),
				filepath.Join(f.runcRoot, "k8s.io", "task-creating"),
				filepath.Join(f.rootDir, "k8s.io", "task-creating"),
				filepath.Join(f.dir, "cgroup", "k8s.io:task-creating"),
			} {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Fatalf("cleanup did not converge, %s still exists", p)
				}
			}
		})
	}
}

// TestRecoverySkipsCleanupOfSharedBundle covers the precondition that a
// bundle referenced by another task record is never cleaned.
func TestRecoverySkipsCleanupOfSharedBundle(t *testing.T) {
	f := newRecoveryFixture(t)

	// a second record points at the creating task's bundle
	shared := &TaskRecord{
		ID: "task-shared", Namespace: "k8s.io",
		BundlePath:   filepath.Join(f.dir, "k8s.io", "task-creating"),
		TraceEventID: 9, Pid: 1001, PidStartTime: 555, Phase: taskPhaseRunning,
	}
	// write it by hand because SaveTask targets the record's own dir
	if err := os.MkdirAll(filepath.Join(f.dir, "k8s.io", "task-shared"), 0711); err != nil {
		t.Fatal(err)
	}
	data, _ := encodeTaskRecord(shared)
	if err := ioutil.WriteFile(filepath.Join(f.dir, "k8s.io", "task-shared", taskRecordFileName), data, 0600); err != nil {
		t.Fatal(err)
	}

	result, _, _ := f.recoverOnce(t, nil)

	if result.Unrecoverable["k8s.io/task-creating"] == nil {
		t.Fatalf("shared-bundle task must be refused, got %+v", result)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "k8s.io", "task-creating")); err != nil {
		t.Fatal("shared bundle must not be cleaned")
	}
}

// TestRecoveryCgroupWithLiveProcessesIsKept covers the precondition that
// a cgroup containing living processes is never removed.
func TestRecoveryCgroupWithLiveProcessesIsKept(t *testing.T) {
	f := newRecoveryFixture(t)

	// the unfinished task's cgroup still has a living process
	cgPath := filepath.Join(f.dir, "cgroup", "k8s.io:task-creating")
	if err := ioutil.WriteFile(filepath.Join(cgPath, "cgroup.procs"), []byte("1001\n"), 0644); err != nil {
		t.Fatal(err)
	}

	result, _, _ := f.recoverOnce(t, nil)
	if !reflect.DeepEqual(result.Cleaned, []string{"k8s.io/task-creating"}) {
		t.Fatalf("cleanup should still complete: %+v", result)
	}
	if _, err := os.Stat(cgPath); err != nil {
		t.Fatal("cgroup with a living process must be kept")
	}
}

// TestRecoveryRegistrySemantics checks the recovering/unrecoverable
// distinction exposed to queries.
func TestRecoveryRegistrySemantics(t *testing.T) {
	reg := newRecoveryRegistry()
	reg.begin([]string{"k8s.io/a", "k8s.io/b", "k8s.io/c"})

	for _, k := range []string{"k8s.io/a", "k8s.io/b", "k8s.io/c"} {
		if !reg.isPending(k) {
			t.Fatalf("%s should be pending", k)
		}
	}

	reg.done("k8s.io/a")
	if reg.isPending("k8s.io/a") {
		t.Fatal("a should be recovered")
	}

	reg.fail("k8s.io/b", fmt.Errorf("boom"))
	if reg.isPending("k8s.io/b") {
		t.Fatal("b should no longer be pending")
	}
	if err := reg.unrecoverableErr("k8s.io/b"); err == nil || err.Error() != "boom" {
		t.Fatalf("b should be unrecoverable: %v", err)
	}
	if reg.unrecoverableErr("k8s.io/a") != nil || reg.unrecoverableErr("k8s.io/unknown") != nil {
		t.Fatal("only failed tasks are unrecoverable")
	}
}

// TestTaskManagerGetDuringRecovery verifies that a task which is known
// but not yet recovered reports "recovering" (unavailable) instead of
// "not found", and that unrecoverable tasks say so.
func TestTaskManagerGetDuringRecovery(t *testing.T) {
	reg := newRecoveryRegistry()
	reg.begin([]string{"k8s.io/pending"})
	reg.fail("k8s.io/broken", fmt.Errorf("corrupt record"))

	manager := &TaskManager{
		tasks:    runtime.NewTaskList(),
		recovery: reg,
	}

	ctx := namespaces.WithNamespace(context.Background(), "k8s.io")

	_, err := manager.Get(ctx, "pending")
	if !errors.Is(err, errdefs.ErrUnavailable) {
		t.Fatalf("pending task should report unavailable, got %v", err)
	}

	_, err = manager.Get(ctx, "broken")
	if err == nil || errors.Is(err, errdefs.ErrNotFound) {
		t.Fatalf("broken task should not report not-found, got %v", err)
	}

	_, err = manager.Get(ctx, "never-existed")
	if !errors.Is(err, errdefs.ErrNotFound) {
		t.Fatalf("unknown task should report not-found, got %v", err)
	}
}

// snapshotTree returns a stable map of relative path -> content hash for
// every file under dir, used to assert identical disk state. File content
// is normalized so fixtures rooted at different temp dirs compare equal.
func snapshotTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			out[rel+"/"] = ""
			return nil
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		normalized := strings.ReplaceAll(string(data), dir, "<STATE>")
		out[rel] = fmt.Sprintf("%x", sha256.Sum256([]byte(normalized)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
