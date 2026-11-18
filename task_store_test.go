package embedshim

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testTaskRecord(ns, id string) *TaskRecord {
	return &TaskRecord{
		ID:           id,
		Namespace:    ns,
		BundlePath:   filepath.Join("/state", ns, id),
		TraceEventID: 42,
		Pid:          1234,
		PidStartTime: 987654,
		Phase:        taskPhaseRunning,
		CreatedAt:    time.Date(2026, 11, 19, 1, 2, 3, 0, time.UTC),
		Stdio:        stdioRecord{Stdin: "/run/fifo/in", Stdout: "/run/fifo/out"},
	}
}

func TestTaskStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := newFileStateStore(dir, nil)

	rec := testTaskRecord("k8s.io", "abc")
	if err := store.SaveTask(rec); err != nil {
		t.Fatal(err)
	}

	got, err := store.LoadTask("k8s.io", "abc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != currentTaskRecordVersion {
		t.Fatalf("expected version %d, got %d", currentTaskRecordVersion, got.Version)
	}
	if got.ID != rec.ID || got.Pid != rec.Pid || got.PidStartTime != rec.PidStartTime ||
		got.Phase != rec.Phase || got.Stdio.Stdin != rec.Stdio.Stdin || !got.CreatedAt.Equal(rec.CreatedAt) {
		t.Fatalf("round trip mismatch: %+v", got)
	}

	// exec records
	execRec := &ExecRecord{
		ID: "exec1", TaskID: "abc", TraceEventID: 43,
		Pid: 1235, PidStartTime: 987700, Phase: execPhaseRunning,
	}
	if err := store.SaveExec("k8s.io", "abc", execRec); err != nil {
		t.Fatal(err)
	}
	execs, unrec, err := store.LoadExecs("k8s.io", "abc")
	if err != nil {
		t.Fatal(err)
	}
	if len(unrec) != 0 || len(execs) != 1 || execs[0].ID != "exec1" || execs[0].Pid != 1235 {
		t.Fatalf("exec round trip mismatch: %+v %+v", execs, unrec)
	}

	// listing
	listed, err := store.ListTasks()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tasks) != 1 || len(listed.Unrecoverable) != 0 {
		t.Fatalf("expected 1 task and no unrecoverable, got %+v", listed)
	}

	// deletes are idempotent
	for i := 0; i < 2; i++ {
		if err := store.DeleteTask("k8s.io", "abc"); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteExec("k8s.io", "abc", "exec1"); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTaskStoreInterruptedWriteLeavesTempFile simulates a host crash
// between the temp-file write and the atomic rename: the partial *.tmp-*
// file stays behind, and recovery must ignore it and still see the last
// good record.
func TestTaskStoreInterruptedWriteLeavesTempFile(t *testing.T) {
	dir := t.TempDir()

	// last good record written without faults
	good := testTaskRecord("k8s.io", "abc")
	good.Phase = taskPhaseCreated
	if err := newFileStateStore(dir, nil).SaveTask(good); err != nil {
		t.Fatal(err)
	}

	// crash exactly after the temp file is written, before the rename
	inj := &crashInjector{point: faultStoreTaskWriteTmp}
	crashed := expectCrash(t, func() {
		bad := testTaskRecord("k8s.io", "abc")
		bad.Phase = taskPhaseRunning
		_ = newFileStateStore(dir, inj).SaveTask(bad)
	})
	if !crashed {
		t.Fatal("expected simulated crash")
	}

	// the temp leftover exists
	matches, err := filepath.Glob(filepath.Join(dir, "k8s.io", "abc", taskRecordFileName+recordTempSuffix+"*"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("expected temp leftover, matches=%v err=%v", matches, err)
	}

	// a fresh store over the same dir sees the last good record, not the
	// half-written one
	listed, err := newFileStateStore(dir, nil).ListTasks()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tasks) != 1 || listed.Tasks[0].Phase != taskPhaseCreated {
		t.Fatalf("expected last good record, got %+v", listed.Tasks)
	}
	if len(listed.Unrecoverable) != 0 {
		t.Fatalf("temp leftover must not be treated as corruption: %+v", listed.Unrecoverable)
	}
}

// TestTaskStoreCorruptRecordIsQuarantined covers a damaged record file:
// the task is reported unrecoverable, the data is kept (renamed aside),
// and other tasks still load.
func TestTaskStoreCorruptRecordIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	store := newFileStateStore(dir, nil)

	if err := store.SaveTask(testTaskRecord("k8s.io", "good")); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTask(testTaskRecord("k8s.io", "bad")); err != nil {
		t.Fatal(err)
	}

	// truncate the record to simulate a torn write that survived as the
	// final name (e.g. non-atomic filesystem)
	badPath := filepath.Join(dir, "k8s.io", "bad", taskRecordFileName)
	if err := ioutil.WriteFile(badPath, []byte(`{"version": 1, "id": "ba`), 0600); err != nil {
		t.Fatal(err)
	}

	listed, err := newFileStateStore(dir, nil).ListTasks()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tasks) != 1 || listed.Tasks[0].ID != "good" {
		t.Fatalf("expected only the good task, got %+v", listed.Tasks)
	}
	if len(listed.Unrecoverable) != 1 {
		t.Fatalf("expected 1 unrecoverable record, got %+v", listed.Unrecoverable)
	}

	u := listed.Unrecoverable[0]
	if u.ID != "bad" || u.Namespace != "k8s.io" {
		t.Fatalf("unrecoverable record not attributed: %+v", u)
	}
	var serr *StateError
	if !errors.As(u.Err, &serr) || serr.Kind != StateErrorCorrupt {
		t.Fatalf("expected corrupt state error, got %v", u.Err)
	}

	// data preserved under the quarantine name, original path gone
	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Fatalf("original record should be renamed aside, stat err=%v", err)
	}
	data, err := ioutil.ReadFile(badPath + quarantinedSuffix)
	if err != nil {
		t.Fatalf("quarantined data must be kept: %v", err)
	}
	if !strings.HasPrefix(string(data), `{"version": 1, "id": "ba`) {
		t.Fatalf("quarantined content mismatch: %q", data)
	}

	// quarantine is stable: a second scan does not re-report or fail
	listed, err = newFileStateStore(dir, nil).ListTasks()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tasks) != 1 || len(listed.Unrecoverable) != 0 {
		t.Fatalf("quarantined record must be skipped on rescan: %+v", listed)
	}
}

// TestTaskStoreUnknownVersion covers a record written by a newer release.
func TestTaskStoreUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	store := newFileStateStore(dir, nil)

	if err := store.SaveTask(testTaskRecord("k8s.io", "future")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "k8s.io", "future", taskRecordFileName)
	data, _ := ioutil.ReadFile(path)
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m["version"] = float64(currentTaskRecordVersion + 1)
	data, _ = json.Marshal(m)
	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	listed, err := newFileStateStore(dir, nil).ListTasks()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Unrecoverable) != 1 {
		t.Fatalf("expected unrecoverable record, got %+v", listed)
	}
	var serr *StateError
	if !errors.As(listed.Unrecoverable[0].Err, &serr) || serr.Kind != StateErrorUnknownVersion {
		t.Fatalf("expected unknown-version error, got %v", listed.Unrecoverable[0].Err)
	}
}

// TestTaskStoreMigrationFromV0 covers reading an old-layout record: it is
// migrated forward, with the process identity marked unknown so the
// recoverer falls back to the shared reconciliation checks.
func TestTaskStoreMigrationFromV0(t *testing.T) {
	dir := t.TempDir()

	v0 := taskRecordV0{
		ID: "legacy", Namespace: "k8s.io",
		BundlePath:   filepath.Join(dir, "k8s.io", "legacy"),
		TraceEventID: 7, Pid: 4321, Phase: taskPhaseRunning,
	}
	data, _ := json.Marshal(v0)
	recDir := filepath.Join(dir, "k8s.io", "legacy")
	if err := os.MkdirAll(recDir, 0711); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(filepath.Join(recDir, taskRecordFileName), data, 0600); err != nil {
		t.Fatal(err)
	}

	listed, err := newFileStateStore(dir, nil).ListTasks()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tasks) != 1 || len(listed.Unrecoverable) != 0 {
		t.Fatalf("expected migrated record, got %+v", listed)
	}
	got := listed.Tasks[0]
	if got.Version != currentTaskRecordVersion || got.ID != "legacy" || got.Pid != 4321 {
		t.Fatalf("migration mismatch: %+v", got)
	}
	if got.PidStartTime != 0 {
		t.Fatalf("migrated record must have unknown start time, got %d", got.PidStartTime)
	}
}

// TestTaskStoreMigrationFailure covers an old record that cannot be
// migrated: unrecoverable, quarantined, data kept.
func TestTaskStoreMigrationFailure(t *testing.T) {
	dir := t.TempDir()

	// v0 record without an id cannot be migrated
	data, _ := json.Marshal(map[string]interface{}{
		"namespace": "k8s.io", "pid": 1, "phase": "running",
	})
	recDir := filepath.Join(dir, "k8s.io", "broken")
	if err := os.MkdirAll(recDir, 0711); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(recDir, taskRecordFileName)
	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	listed, err := newFileStateStore(dir, nil).ListTasks()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Unrecoverable) != 1 {
		t.Fatalf("expected unrecoverable record, got %+v", listed)
	}
	var serr *StateError
	if !errors.As(listed.Unrecoverable[0].Err, &serr) || serr.Kind != StateErrorMigrationFailed {
		t.Fatalf("expected migration-failed error, got %v", listed.Unrecoverable[0].Err)
	}
	if _, err := os.Stat(path + quarantinedSuffix); err != nil {
		t.Fatalf("data must be kept after failed migration: %v", err)
	}
}

// TestParseProcStatStartTime checks the /proc/<pid>/stat parser against
// comm values containing spaces and parentheses.
func TestParseProcStatStartTime(t *testing.T) {
	for name, tc := range map[string]struct {
		stat string
		want uint64
	}{
		"simple": {"1234 (runc-init) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20", 424242},
		"spaces": {"1234 (my weird proc) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 20", 777},
		"parens": {"1234 (weird)name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 888 20", 888},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseProcStatStartTime(tc.stat)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("want %d, got %d", tc.want, got)
			}
		})
	}

	if _, err := parseProcStatStartTime("garbage"); err == nil {
		t.Fatal("expected error for malformed stat")
	}
}

// TestProcInspectorAgainstRealProc sanity-checks the production inspector
// against the real /proc.
func TestProcInspectorAgainstRealProc(t *testing.T) {
	insp := procInspector{}
	if _, err := insp.StartTime(os.Getpid()); err != nil {
		t.Fatalf("self must exist: %v", err)
	}
	if _, err := insp.StartTime(1 << 22); err != errProcessNotExist {
		t.Fatalf("expected errProcessNotExist, got %v", err)
	}
}
