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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

// errProcessNotExist is returned by processInspector when the pid is gone.
var errProcessNotExist = errors.New("process does not exist")

// processInspector resolves the identity of a process. It is injectable so
// recovery can be tested without real processes: the production
// implementation reads /proc, tests use a table.
type processInspector interface {
	// StartTime returns the start-time identifier of the process (the
	// value that, together with the pid, uniquely identifies a process
	// instance across pid reuse). It returns errProcessNotExist when the
	// process is gone.
	StartTime(pid int) (uint64, error)
}

// procInspector is the production processInspector backed by /proc.
type procInspector struct{}

// StartTime reads field 22 (starttime, in clock ticks since boot) of
// /proc/<pid>/stat. Two processes with the same pid but different
// starttimes are different instances: the pid was reused.
func (procInspector) StartTime(pid int) (uint64, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, errProcessNotExist
		}
		return 0, err
	}
	return parseProcStatStartTime(string(data))
}

// parseProcStatStartTime extracts the starttime field. The comm field
// (field 2) is parenthesized and may contain spaces or ')', so parsing
// starts after the last ')'.
func parseProcStatStartTime(stat string) (uint64, error) {
	end := strings.LastIndex(stat, ")")
	if end < 0 || end+2 >= len(stat) {
		return 0, fmt.Errorf("malformed /proc stat content")
	}
	fields := strings.Fields(stat[end+1:])
	// fields[0] is now field 3 (state); starttime is field 22.
	const startTimeIdx = 22 - 3
	if len(fields) <= startTimeIdx {
		return 0, fmt.Errorf("malformed /proc stat content: not enough fields")
	}
	v, err := strconv.ParseUint(fields[startTimeIdx], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse starttime: %w", err)
	}
	return v, nil
}
