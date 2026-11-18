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
	"encoding/json"
	"fmt"
	"time"
)

// currentTaskRecordVersion is the latest on-disk layout version. Bump it
// whenever the layout changes and add a migration step in migrateTaskRecord.
const currentTaskRecordVersion = 1

// Task phases persisted on disk. The phase is the recovery hint: it tells
// the recoverer whether the task ever became a real process (creating vs
// the rest) and which in-memory state machine to rebuild.
const (
	// taskPhaseCreating means the record was written before the init
	// process was successfully created. A record left in this phase after
	// a crash describes an unfinished task whose resources are leftovers
	// to clean, not a task to recover.
	taskPhaseCreating = "creating"
	taskPhaseCreated  = "created"
	taskPhaseRunning  = "running"
	taskPhasePaused   = "paused"
	taskPhaseStopped  = "stopped"
)

// Exec phases persisted on disk.
const (
	execPhaseCreated = "created"
	execPhaseRunning = "running"
	execPhaseStopped = "stopped"
)

// StateErrorKind classifies why a persisted record could not be loaded.
type StateErrorKind int

const (
	// StateErrorCorrupt means the file content is not decodable (truncated
	// write, bit rot, ...).
	StateErrorCorrupt StateErrorKind = iota
	// StateErrorUnknownVersion means the record was written by a newer
	// version of embedshim and this build does not know how to read it.
	StateErrorUnknownVersion
	// StateErrorMigrationFailed means the record is old and the migration
	// to the current version failed.
	StateErrorMigrationFailed
)

func (k StateErrorKind) String() string {
	switch k {
	case StateErrorCorrupt:
		return "corrupt"
	case StateErrorUnknownVersion:
		return "unknown-version"
	case StateErrorMigrationFailed:
		return "migration-failed"
	}
	return "unknown"
}

// StateError describes an unrecoverable persisted record. Records failing
// with a StateError must be quarantined (kept, but renamed aside) and
// alerted on; they must never be silently deleted and must never abort the
// recovery of other tasks.
type StateError struct {
	Kind StateErrorKind
	Path string
	Err  error
}

func (e *StateError) Error() string {
	return fmt.Sprintf("state record %s is unrecoverable (%s): %v", e.Path, e.Kind, e.Err)
}

func (e *StateError) Unwrap() error { return e.Err }

// stdioRecord is the persisted view of a process's standard streams.
type stdioRecord struct {
	Stdin    string `json:"stdin,omitempty"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Terminal bool   `json:"terminal,omitempty"`
}

// TaskRecord is the persistent identity of a task. It is written before
// the init process is created (phase=creating) and updated on every phase
// transition, so that after a host crash the recoverer can rebuild exactly
// what the user saw before the restart.
type TaskRecord struct {
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Namespace string `json:"namespace"`

	// BundlePath is the on-disk bundle (state) directory of the task.
	BundlePath string `json:"bundlePath"`

	// TraceEventID identifies the task in the exitsnoop reconciliation
	// mechanism; exit events are replayed through it after a restart.
	TraceEventID uint64 `json:"traceEventID"`

	// Pid is the init process pid. PidStartTime is the process start-time
	// identifier (/proc/<pid>/stat field 22): a pid is only considered the
	// same process if both match, which protects against pid reuse. A zero
	// PidStartTime means the identity is unknown (migrated record) and the
	// shared reconciliation mechanism must verify it instead.
	Pid          int    `json:"pid,omitempty"`
	PidStartTime uint64 `json:"pidStartTime,omitempty"`

	Phase     string      `json:"phase"`
	CreatedAt time.Time   `json:"createdAt"`
	Stdio     stdioRecord `json:"stdio"`

	// CgroupPaths are best-effort hints (relative to the cgroup mount)
	// used by the leftover cleaner. They are only removed when provably
	// empty.
	CgroupPaths []string `json:"cgroupPaths,omitempty"`
}

// ExecRecord is the persistent identity of an exec (attached) process.
type ExecRecord struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	TaskID  string `json:"taskID"`

	TraceEventID uint64 `json:"traceEventID"`

	Pid          int    `json:"pid,omitempty"`
	PidStartTime uint64 `json:"pidStartTime,omitempty"`

	Phase     string      `json:"phase"`
	CreatedAt time.Time   `json:"createdAt"`
	Stdio     stdioRecord `json:"stdio"`
}

// taskRecordV0 is the legacy (pre-starttime) layout, kept so the migration
// path is exercised and old state directories remain readable.
type taskRecordV0 struct {
	ID           string      `json:"id"`
	Namespace    string      `json:"namespace"`
	BundlePath   string      `json:"bundlePath"`
	TraceEventID uint64      `json:"traceEventID"`
	Pid          int         `json:"pid"`
	Phase        string      `json:"phase"`
	Stdio        stdioRecord `json:"stdio"`
}

// decodeTaskRecord parses a persisted task record, migrating older
// versions forward. Any failure is reported as a *StateError so the caller
// can quarantine the record instead of failing the whole recovery.
func decodeTaskRecord(path string, data []byte) (*TaskRecord, error) {
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, &StateError{Kind: StateErrorCorrupt, Path: path, Err: err}
	}

	switch {
	case head.Version == currentTaskRecordVersion:
		var rec TaskRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, &StateError{Kind: StateErrorCorrupt, Path: path, Err: err}
		}
		if rec.ID == "" || rec.Namespace == "" {
			return nil, &StateError{Kind: StateErrorCorrupt, Path: path,
				Err: fmt.Errorf("record is missing id or namespace")}
		}
		return &rec, nil

	case head.Version < currentTaskRecordVersion && head.Version >= 0:
		rec, err := migrateTaskRecord(head.Version, data)
		if err != nil {
			return nil, &StateError{Kind: StateErrorMigrationFailed, Path: path, Err: err}
		}
		return rec, nil

	default:
		return nil, &StateError{Kind: StateErrorUnknownVersion, Path: path,
			Err: fmt.Errorf("record version %d is newer than supported version %d",
				head.Version, currentTaskRecordVersion)}
	}
}

// migrateTaskRecord upgrades a persisted record to the current version,
// one step at a time. A migration failure leaves the original file
// untouched; the caller quarantines it and keeps the user's data.
func migrateTaskRecord(version int, data []byte) (*TaskRecord, error) {
	if version != 0 {
		return nil, fmt.Errorf("no migration path from version %d", version)
	}

	var v0 taskRecordV0
	if err := json.Unmarshal(data, &v0); err != nil {
		return nil, fmt.Errorf("failed to decode v0 record: %w", err)
	}
	if v0.ID == "" || v0.Namespace == "" {
		return nil, fmt.Errorf("v0 record is missing id or namespace")
	}

	// v0 -> v1: PidStartTime and CreatedAt did not exist. A zero
	// PidStartTime marks the process identity as unknown; the recoverer
	// then defers to the shared reconciliation mechanism instead of
	// trusting the pid.
	return &TaskRecord{
		Version:      currentTaskRecordVersion,
		ID:           v0.ID,
		Namespace:    v0.Namespace,
		BundlePath:   v0.BundlePath,
		TraceEventID: v0.TraceEventID,
		Pid:          v0.Pid,
		PidStartTime: 0, // unknown identity, verified at recovery time
		Phase:        v0.Phase,
		Stdio:        v0.Stdio,
	}, nil
}

// encodeTaskRecord serializes a record at the current version.
func encodeTaskRecord(rec *TaskRecord) ([]byte, error) {
	rec.Version = currentTaskRecordVersion
	return json.Marshal(rec)
}

// decodeExecRecord parses a persisted exec record. Exec records were
// introduced at version 1, so no migration path exists yet; the version
// check is kept symmetric with task records for future layout changes.
func decodeExecRecord(path string, data []byte) (*ExecRecord, error) {
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, &StateError{Kind: StateErrorCorrupt, Path: path, Err: err}
	}
	if head.Version != currentTaskRecordVersion {
		return nil, &StateError{Kind: StateErrorUnknownVersion, Path: path,
			Err: fmt.Errorf("record version %d is newer than supported version %d",
				head.Version, currentTaskRecordVersion)}
	}

	var rec ExecRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, &StateError{Kind: StateErrorCorrupt, Path: path, Err: err}
	}
	if rec.ID == "" || rec.TaskID == "" {
		return nil, &StateError{Kind: StateErrorCorrupt, Path: path,
			Err: fmt.Errorf("exec record is missing id or task id")}
	}
	return &rec, nil
}

// encodeExecRecord serializes an exec record at the current version.
func encodeExecRecord(rec *ExecRecord) ([]byte, error) {
	rec.Version = currentTaskRecordVersion
	return json.Marshal(rec)
}
