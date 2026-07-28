// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

// IsManagedChainFile reports whether path uses the filename format owned by
// JSONLSink. Legacy native-hook and user-exported JSONL files are deliberately
// excluded from the shared chain.
func IsManagedChainFile(path string) bool {
	_, managed := auditFileSortKey(path)
	return managed
}

// VerifyManagedChain verifies every managed JSONL event and continuation
// header in dir without modifying the audit directory. It accepts the
// out-of-file-order layout produced when older Rampart versions reopened a
// daily base file after size rotation.
func VerifyManagedChain(dir string) (int64, error) {
	state, err := recoverChainStateFromDir(dir, nil)
	if err != nil {
		return 0, err
	}
	return state.eventCount, nil
}
