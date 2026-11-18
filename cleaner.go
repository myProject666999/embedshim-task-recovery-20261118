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
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
)

// Fault-injection point names used by the cleaner.
const (
	faultCleanBegin        = "clean.begin"
	faultCleanUnmounted    = "clean.unmounted"
	faultCleanPathsRemoved = "clean.paths-removed"
	faultCleanCgroupDone   = "clean.cgroup-done"
	faultCleanBundleDone   = "clean.bundle-removed"
)

// cleanerOps abstracts the side effects of leftover cleanup so tests can
// run them against a fake filesystem view and inject crashes between
// steps. The production implementation is sysCleanerOps.
type cleanerOps interface {
	// UnmountAll lazily unmounts everything under target. It must be a
	// no-op when nothing is mounted there.
	UnmountAll(target string) error
	// RemoveAll removes a path tree. It must be a no-op when the path is
	// already gone.
	RemoveAll(path string) error
	// CgroupPids returns the pids still living in the cgroup, or nil when
	// the cgroup is empty or gone.
	CgroupPids(cgroupPath string) ([]int, error)
	// RemoveCgroup removes an empty cgroup directory. It must be a no-op
	// when the cgroup is already gone.
	RemoveCgroup(cgroupPath string) error
}

// sysCleanerOps is the production cleanerOps.
type sysCleanerOps struct {
	procs processInspector
}

func (sysCleanerOps) UnmountAll(target string) error {
	return mount.UnmountAll(target, 0)
}

func (sysCleanerOps) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

func (o sysCleanerOps) CgroupPids(cgroupPath string) ([]int, error) {
	data, err := ioutil.ReadFile(filepath.Join(cgroupPath, "cgroup.procs"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var alive []int
	for _, line := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
		// A pid listed in cgroup.procs may already be a zombie of a
		// reused pid; only count processes that actually exist.
		if o.procs != nil {
			if _, err := o.procs.StartTime(pid); err != nil {
				continue
			}
		}
		alive = append(alive, pid)
	}
	return alive, nil
}

func (sysCleanerOps) RemoveCgroup(cgroupPath string) error {
	err := os.Remove(cgroupPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// leftoverCleaner removes resources of tasks that are confirmed to never
// have started (phase=creating leftovers) or confirmed to be gone. Every
// step is idempotent so cleanup can be re-run after a crash at any point.
//
// Preconditions, enforced before anything is removed:
//   - the task record proves the task never became a running process, or
//     the process is confirmed gone by the recoverer (the caller's duty);
//   - the bundle directory is not referenced by any other task record;
//   - a cgroup is only removed when it contains no living process.
type leftoverCleaner struct {
	ops   cleanerOps
	hooks faultHooks

	// runcStateRoot is the runc runtime state root (per-namespace dirs
	// holding exec.fifo and friends).
	runcStateRoot string
	// rootDir is the embedshim root dir holding the per-task work dirs.
	rootDir string
}

func newLeftoverCleaner(ops cleanerOps, runcStateRoot, rootDir string, hooks faultHooks) *leftoverCleaner {
	return &leftoverCleaner{
		ops:           ops,
		runcStateRoot: runcStateRoot,
		rootDir:       rootDir,
		hooks:         hooks,
	}
}

// Clean removes the leftovers of one task record. It is safe to call
// repeatedly: every step tolerates already-removed resources, so a crash
// between any two steps does not change the final outcome.
func (c *leftoverCleaner) Clean(ctx context.Context, rec *TaskRecord) error {
	lg := log.G(ctx).WithField("task", rec.ID).WithField("namespace", rec.Namespace)
	hitFault(c.hooks, faultCleanBegin)

	// 1. Mounts: a half-created task may have left the rootfs (or
	//    sub-mounts) mounted. UnmountAll is lazy and a no-op when nothing
	//    is mounted, and it never touches mounts outside the target tree,
	//    so mounts still used by other containers are safe.
	rootfs := filepath.Join(rec.BundlePath, "rootfs")
	if err := c.ops.UnmountAll(rootfs); err != nil {
		lg.WithError(err).Warn("cleanup: failed to unmount rootfs, retry next recovery")
		return err
	}
	hitFault(c.hooks, faultCleanUnmounted)

	// 2. File-descriptor related paths: the runc state dir holds the
	//    temporary exec.fifo the init process was syncing on; the work
	//    dir holds the runtime log and the extracted bundle work files.
	//    Both are per-task.
	for _, p := range []string{
		filepath.Join(c.runcStateRoot, rec.Namespace, rec.ID),
		filepath.Join(c.rootDir, rec.Namespace, rec.ID),
	} {
		if err := c.ops.RemoveAll(p); err != nil {
			lg.WithError(err).Warnf("cleanup: failed to remove %s, retry next recovery", p)
			return err
		}
	}
	hitFault(c.hooks, faultCleanPathsRemoved)

	// 3. Cgroups: only removed when provably empty. A cgroup that still
	//    contains a living process belongs to a workload that outlived
	//    the task record and must not be touched.
	for _, cgPath := range rec.CgroupPaths {
		pids, err := c.ops.CgroupPids(cgPath)
		if err != nil {
			lg.WithError(err).Warnf("cleanup: failed to inspect cgroup %s, skip", cgPath)
			continue
		}
		if len(pids) > 0 {
			lg.Warnf("cleanup: cgroup %s still has %d living processes, skip", cgPath, len(pids))
			continue
		}
		if err := c.ops.RemoveCgroup(cgPath); err != nil {
			lg.WithError(err).Warnf("cleanup: failed to remove cgroup %s, skip", cgPath)
		}
	}
	hitFault(c.hooks, faultCleanCgroupDone)

	// 4. The bundle directory itself, last: it contains the task record,
	//    and the record is what makes a crash anywhere above recoverable
	//    by re-running this exact cleanup.
	if err := c.ops.RemoveAll(rec.BundlePath); err != nil {
		lg.WithError(err).Warn("cleanup: failed to remove bundle, retry next recovery")
		return err
	}
	hitFault(c.hooks, faultCleanBundleDone)
	return nil
}

// bundleReferencedByOthers reports whether another live record points at
// the same bundle path. Cleaning a bundle that a second task still
// references would destroy that task's state, so such records are skipped.
func bundleReferencedByOthers(rec *TaskRecord, all []*TaskRecord) bool {
	for _, other := range all {
		if other.ID == rec.ID && other.Namespace == rec.Namespace {
			continue
		}
		if other.BundlePath == rec.BundlePath {
			return true
		}
	}
	return false
}
