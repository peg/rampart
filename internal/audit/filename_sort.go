// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package audit

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SortAuditFiles sorts audit JSONL files in chronological rotation order.
//
// Size-rotated files are named YYYY-MM-DD.pN.jsonl. A plain lexicographic sort
// places .p10 before .p2, which can replay and recover hash-chain state in the
// wrong order. Unknown legacy filenames retain lexicographic fallback ordering.
func SortAuditFiles(files []string) {
	sort.SliceStable(files, func(i, j int) bool {
		return compareAuditFile(files[i], files[j]) < 0
	})
}

func compareAuditFile(a, b string) int {
	ak, aok := auditFileSortKey(a)
	bk, bok := auditFileSortKey(b)
	if aok && bok {
		if ak.date != bk.date {
			return strings.Compare(ak.date, bk.date)
		}
		if ak.seq != bk.seq {
			if ak.seq < bk.seq {
				return -1
			}
			return 1
		}
	}

	abase := filepath.Base(a)
	bbase := filepath.Base(b)
	if abase < bbase {
		return -1
	}
	if abase > bbase {
		return 1
	}
	return 0
}

type auditFileKey struct {
	date string
	seq  int
}

func auditFileSortKey(path string) (auditFileKey, bool) {
	name := filepath.Base(path)
	if !strings.HasSuffix(name, ".jsonl") {
		return auditFileKey{}, false
	}
	stem := strings.TrimSuffix(name, ".jsonl")
	if len(stem) < len("2006-01-02") {
		return auditFileKey{}, false
	}

	date := stem[:len("2006-01-02")]
	if _, err := time.Parse("2006-01-02", date); err != nil {
		return auditFileKey{}, false
	}

	rest := stem[len("2006-01-02"):]
	if rest == "" {
		return auditFileKey{date: date, seq: 0}, true
	}
	if !strings.HasPrefix(rest, ".p") {
		return auditFileKey{}, false
	}
	seq, err := strconv.Atoi(strings.TrimPrefix(rest, ".p"))
	if err != nil || seq < 1 {
		return auditFileKey{}, false
	}
	return auditFileKey{date: date, seq: seq}, true
}
