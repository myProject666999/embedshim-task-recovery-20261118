package embedshim

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// recordingCleanerOps logs the order of operations and delegates to the
// filesystem.
type recordingCleanerOps struct {
	fsCleanerOps
	order []string
}

func (o *recordingCleanerOps) UnmountAll(target string) error {
	o.order = append(o.order, "unmount "+target)
	return o.fsCleanerOps.UnmountAll(target)
}

func (o *recordingCleanerOps) RemoveAll(path string) error {
	o.order = append(o.order, "removeall "+filepath.Base(path))
	return o.fsCleanerOps.RemoveAll(path)
}

func (o *recordingCleanerOps) RemoveCgroup(path string) error {
	o.order = append(o.order, "removecgroup "+filepath.Base(path))
	return o.fsCleanerOps.RemoveCgroup(path)
}

// TestCleanerRemovesBundleLast pins the ordering that makes cleanup
// crash-safe: the task record lives in the bundle, so the bundle must be
// the last thing to go.
func TestCleanerRemovesBundleLast(t *testing.T) {
	dir := t.TempDir()
	procs := &fakeProcs{startTimes: map[int]uint64{}}
	ops := &recordingCleanerOps{fsCleanerOps: fsCleanerOps{procs: procs}}

	bundle := filepath.Join(dir, "k8s.io", "t1")
	cg := filepath.Join(dir, "cgroup", "k8s.io:t1")
	for _, d := range []string{
		filepath.Join(bundle, "rootfs"),
		filepath.Join(dir, "runc", "k8s.io", "t1"),
		filepath.Join(dir, "root", "k8s.io", "t1"),
		cg,
	} {
		if err := os.MkdirAll(d, 0711); err != nil {
			t.Fatal(err)
		}
	}
	if err := ioutil.WriteFile(filepath.Join(cg, "cgroup.procs"), nil, 0644); err != nil {
		t.Fatal(err)
	}

	rec := &TaskRecord{
		ID: "t1", Namespace: "k8s.io", BundlePath: bundle,
		Phase: taskPhaseCreating, CgroupPaths: []string{cg},
	}
	cleaner := newLeftoverCleaner(ops, filepath.Join(dir, "runc"), filepath.Join(dir, "root"), nil)

	// run twice: the second run must be a clean no-op
	for i := 0; i < 2; i++ {
		if err := cleaner.Clean(context.Background(), rec); err != nil {
			t.Fatalf("clean run %d: %v", i, err)
		}
	}

	// the bundle (holding the record) is removed, and removed last
	if len(ops.order) == 0 {
		t.Fatal("expected cleanup operations")
	}
	last := ops.order[len(ops.order)-1]
	if last != "removeall t1" {
		t.Fatalf("bundle must be removed last, order: %v", ops.order)
	}
	for _, p := range []string{bundle, cg, filepath.Join(dir, "runc", "k8s.io", "t1")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s should be gone", p)
		}
	}

	// unmount targeted the rootfs
	wantUnmount := "unmount " + filepath.Join(bundle, "rootfs")
	if ops.order[0] != wantUnmount {
		t.Fatalf("first op should be %q, got %v", wantUnmount, ops.order)
	}
}

// TestCleanerOpsPreconditions covers the guard rails directly: live
// cgroup kept, empty cgroup removed, missing resources tolerated.
func TestCleanerOpsPreconditions(t *testing.T) {
	dir := t.TempDir()
	procs := &fakeProcs{startTimes: map[int]uint64{4242: 1}}
	ops := &fsCleanerOps{procs: procs}

	// live cgroup
	liveCg := filepath.Join(dir, "live")
	if err := os.MkdirAll(liveCg, 0755); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(filepath.Join(liveCg, "cgroup.procs"), []byte("4242\n"), 0644); err != nil {
		t.Fatal(err)
	}
	pids, err := ops.CgroupPids(liveCg)
	if err != nil || !reflect.DeepEqual(pids, []int{4242}) {
		t.Fatalf("expected live pid 4242, got %v err=%v", pids, err)
	}

	// dead pids in cgroup.procs do not count
	deadCg := filepath.Join(dir, "dead")
	if err := os.MkdirAll(deadCg, 0755); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(filepath.Join(deadCg, "cgroup.procs"), []byte("9999\n"), 0644); err != nil {
		t.Fatal(err)
	}
	pids, err = ops.CgroupPids(deadCg)
	if err != nil || len(pids) != 0 {
		t.Fatalf("expected no live pids, got %v err=%v", pids, err)
	}

	// missing cgroup is empty, removal is a no-op
	pids, err = ops.CgroupPids(filepath.Join(dir, "gone"))
	if err != nil || len(pids) != 0 {
		t.Fatalf("expected no pids for missing cgroup, got %v err=%v", pids, err)
	}
	if err := ops.RemoveCgroup(filepath.Join(dir, "gone")); err != nil {
		t.Fatal(err)
	}
	if err := ops.RemoveAll(filepath.Join(dir, "gone")); err != nil {
		t.Fatal(err)
	}
}
