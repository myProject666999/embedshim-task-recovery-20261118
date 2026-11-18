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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const (
	// taskRecordFileName is the per-task record inside the bundle state dir.
	taskRecordFileName = "task.json"
	// execRecordFilePrefix prefixes per-exec records inside the bundle dir.
	execRecordFilePrefix = "exec."
	// recordTempSuffix marks in-flight atomic writes. Files with this
	// suffix are leftovers of an interrupted write and are never complete.
	recordTempSuffix = ".tmp-"
	// quarantinedSuffix marks records that failed to load. The data is
	// kept for inspection but excluded from further recovery attempts.
	quarantinedSuffix = ".corrupt"
)

// faultHooks is a test-only injection point. Every step of persistence and
// recovery calls Hit with a stable point name; the production build passes
// nil. Tests install a hook that panics with a simulated crash, drops all
// in-memory objects and re-runs recovery from the same state directory.
type faultHooks interface {
	Hit(point string)
}

// Fault-injection point names used by the store.
const (
	faultStoreTaskWriteTmp    = "store.task.write-tmp"
	faultStoreTaskWriteRename = "store.task.write-rename"
)

func hitFault(h faultHooks, point string) {
	if h != nil {
		h.Hit(point)
	}
}

// UnrecoverableRecord is a persisted record that could not be loaded. The
// file has been quarantined (renamed aside, never deleted) and the task it
// described is excluded from recovery.
type UnrecoverableRecord struct {
	Namespace string
	ID        string
	Path      string
	Err       error
}

// TaskListResult is the outcome of scanning the state directory.
type TaskListResult struct {
	Tasks []*TaskRecord
	// Unrecoverable holds records that failed to decode or migrate. The
	// scan itself never fails because of them.
	Unrecoverable []*UnrecoverableRecord
}

// taskStateStore is the injectable persistence backend for task and exec
// records. The production implementation is fileStateStore; tests replace
// it to inject write failures and to simulate crashes.
type taskStateStore interface {
	SaveTask(rec *TaskRecord) error
	LoadTask(ns, id string) (*TaskRecord, error)
	DeleteTask(ns, id string) error
	ListTasks() (*TaskListResult, error)

	SaveExec(ns, taskID string, rec *ExecRecord) error
	LoadExecs(ns, taskID string) ([]*ExecRecord, []*UnrecoverableRecord, error)
	DeleteExec(ns, taskID, execID string) error
}

// fileStateStore persists records as JSON files inside the bundle state
// directory: <stateDir>/<ns>/<id>/task.json and
// <stateDir>/<ns>/<id>/exec.<execID>.json. Writes go to a temporary file
// in the same directory, are fsynced and then atomically renamed, so a
// host crash can leave a *.tmp-* file behind but never a half-written
// record.
type fileStateStore struct {
	stateDir string
	hooks    faultHooks
}

func newFileStateStore(stateDir string, hooks faultHooks) *fileStateStore {
	return &fileStateStore{stateDir: stateDir, hooks: hooks}
}

func (s *fileStateStore) bundleDir(ns, id string) string {
	return filepath.Join(s.stateDir, ns, id)
}

func (s *fileStateStore) taskRecordPath(ns, id string) string {
	return filepath.Join(s.bundleDir(ns, id), taskRecordFileName)
}

func (s *fileStateStore) execRecordPath(ns, taskID, execID string) string {
	return filepath.Join(s.bundleDir(ns, taskID), execRecordFilePrefix+execID+".json")
}

func (s *fileStateStore) SaveTask(rec *TaskRecord) error {
	data, err := encodeTaskRecord(rec)
	if err != nil {
		return err
	}
	path := s.taskRecordPath(rec.Namespace, rec.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0711); err != nil {
		return err
	}
	return s.writeFileAtomic(path, data)
}

func (s *fileStateStore) LoadTask(ns, id string) (*TaskRecord, error) {
	path := s.taskRecordPath(ns, id)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeTaskRecord(path, data)
}

func (s *fileStateStore) DeleteTask(ns, id string) error {
	err := os.Remove(s.taskRecordPath(ns, id))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *fileStateStore) SaveExec(ns, taskID string, rec *ExecRecord) error {
	data, err := encodeExecRecord(rec)
	if err != nil {
		return err
	}
	path := s.execRecordPath(ns, taskID, rec.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0711); err != nil {
		return err
	}
	return s.writeFileAtomic(path, data)
}

func (s *fileStateStore) LoadExecs(ns, taskID string) ([]*ExecRecord, []*UnrecoverableRecord, error) {
	dir := s.bundleDir(ns, taskID)
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	var (
		execs         []*ExecRecord
		unrecoverable []*UnrecoverableRecord
	)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !isExecRecordFile(name) {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		rec, derr := decodeExecRecord(path, data)
		if derr != nil {
			unrecoverable = append(unrecoverable,
				&UnrecoverableRecord{Path: s.quarantine(path), Err: derr})
			continue
		}
		execs = append(execs, rec)
	}
	return execs, unrecoverable, nil
}

func (s *fileStateStore) DeleteExec(ns, taskID, execID string) error {
	err := os.Remove(s.execRecordPath(ns, taskID, execID))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *fileStateStore) ListTasks() (*TaskListResult, error) {
	result := &TaskListResult{}

	nsEntries, err := ioutil.ReadDir(s.stateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return nil, err
	}

	for _, nsEnt := range nsEntries {
		if !nsEnt.IsDir() || strings.HasPrefix(nsEnt.Name(), ".") {
			continue
		}
		nsDir := filepath.Join(s.stateDir, nsEnt.Name())
		taskEntries, err := ioutil.ReadDir(nsDir)
		if err != nil {
			return nil, err
		}
		for _, taskEnt := range taskEntries {
			// Skip hidden dirs (atomic deletes in flight) and anything
			// that is not a bundle directory.
			if !taskEnt.IsDir() || strings.HasPrefix(taskEnt.Name(), ".") {
				continue
			}
			path := filepath.Join(nsDir, taskEnt.Name(), taskRecordFileName)
			data, err := ioutil.ReadFile(path)
			if os.IsNotExist(err) {
				// Bundle without a record: either a legacy
				// (pre-persistence) task or a leftover handled by the
				// legacy reload path.
				continue
			}
			if err != nil {
				return nil, err
			}
			rec, derr := decodeTaskRecord(path, data)
			if derr != nil {
				result.Unrecoverable = append(result.Unrecoverable,
					&UnrecoverableRecord{
						Namespace: nsEnt.Name(),
						ID:        taskEnt.Name(),
						Path:      s.quarantine(path),
						Err:       derr,
					})
				continue
			}
			result.Tasks = append(result.Tasks, rec)
		}
	}
	return result, nil
}

// quarantine renames a broken record aside so recovery does not trip over
// it on every restart. The data is deliberately kept: it is the user's
// only copy of what the task was, and an operator may still recover it by
// hand. Quarantining is idempotent.
func (s *fileStateStore) quarantine(path string) string {
	target := path + quarantinedSuffix
	if err := os.Rename(path, target); err != nil {
		// If the rename fails we still must not delete the data; report
		// the original path.
		return path
	}
	return target
}

// writeFileAtomic writes data to <path>.tmp-<pid> first, fsyncs it, and
// atomically renames it over path, then fsyncs the directory. A crash
// anywhere in the sequence leaves either the old record or a *.tmp-*
// leftover, never a truncated record.
func (s *fileStateStore) writeFileAtomic(path string, data []byte) (retErr error) {
	tmp := fmt.Sprintf("%s%s%d", path, recordTempSuffix, os.Getpid())

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp record %s: %w", tmp, err)
	}
	defer func() {
		if retErr != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("failed to write temp record %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp record %s: %w", tmp, err)
	}

	// Crash point: a host crash here leaves the *.tmp-* file behind. The
	// next recovery ignores it and still sees the previous good record.
	hitFault(s.hooks, faultStoreTaskWriteTmp)

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temp record %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %w", tmp, path, err)
	}

	hitFault(s.hooks, faultStoreTaskWriteRename)

	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func isExecRecordFile(name string) bool {
	return strings.HasPrefix(name, execRecordFilePrefix) &&
		strings.HasSuffix(name, ".json")
}
