// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build windows

package securefile

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func withWindowsACLStubs(t *testing.T) {
	t.Helper()
	originalCurrentProcessUserSID := currentProcessUserSID
	originalACLFromEntries := aclFromEntries
	originalSetNamedSecurityInfo := setNamedSecurityInfo
	t.Cleanup(func() {
		currentProcessUserSID = originalCurrentProcessUserSID
		aclFromEntries = originalACLFromEntries
		setNamedSecurityInfo = originalSetNamedSecurityInfo
	})
}

func TestOwnerOnlyUsesProcessSIDAndProtectedDACL(t *testing.T) {
	withWindowsACLStubs(t)

	sid, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	wantACL := &windows.ACL{}
	currentProcessUserSID = func() (*windows.SID, error) { return sid, nil }
	aclFromEntries = func(entries []windows.EXPLICIT_ACCESS, merged *windows.ACL) (*windows.ACL, error) {
		if merged != nil {
			t.Fatal("owner-only ACL must not merge inherited or existing entries")
		}
		if len(entries) != 1 {
			t.Fatalf("ACL entries = %d, want 1", len(entries))
		}
		entry := entries[0]
		if entry.AccessPermissions != windows.GENERIC_ALL ||
			entry.AccessMode != windows.SET_ACCESS ||
			entry.Inheritance != windows.NO_INHERITANCE {
			t.Fatalf("unexpected owner ACL entry: %#v", entry)
		}
		if entry.Trustee.TrusteeForm != windows.TRUSTEE_IS_SID ||
			entry.Trustee.TrusteeType != windows.TRUSTEE_IS_USER ||
			entry.Trustee.TrusteeValue != windows.TrusteeValueFromSID(sid) {
			t.Fatal("ACL trustee does not use the current process SID")
		}
		return wantACL, nil
	}

	setCalled := false
	setNamedSecurityInfo = func(
		path string,
		objectType windows.SE_OBJECT_TYPE,
		securityInformation windows.SECURITY_INFORMATION,
		owner *windows.SID,
		group *windows.SID,
		dacl *windows.ACL,
		sacl *windows.ACL,
	) error {
		setCalled = true
		if path != `C:\Users\alice\.rampart\signing.key` {
			t.Errorf("path = %q", path)
		}
		if objectType != windows.SE_FILE_OBJECT {
			t.Errorf("object type = %d, want SE_FILE_OBJECT", objectType)
		}
		wantInformation := windows.SECURITY_INFORMATION(
			windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION,
		)
		if securityInformation != wantInformation {
			t.Errorf("security information = %#x, want %#x", securityInformation, wantInformation)
		}
		if owner != nil || group != nil || sacl != nil || dacl != wantACL {
			t.Fatal("unexpected security descriptor mutation")
		}
		return nil
	}

	if err := OwnerOnly(`C:\Users\alice\.rampart\signing.key`); err != nil {
		t.Fatalf("OwnerOnly: %v", err)
	}
	if !setCalled {
		t.Fatal("SetNamedSecurityInfo was not called")
	}
}

func TestOwnerOnlyFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		sidErr  error
		aclErr  error
		setErr  error
		wantErr string
	}{
		{name: "SID lookup", sidErr: errors.New("token unavailable"), wantErr: "get current process user SID"},
		{name: "ACL construction", aclErr: errors.New("invalid ACL"), wantErr: "build owner-only DACL"},
		{name: "ACL application", setErr: errors.New("access denied"), wantErr: "set owner-only DACL"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withWindowsACLStubs(t)
			sid, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
			if err != nil {
				t.Fatal(err)
			}
			currentProcessUserSID = func() (*windows.SID, error) { return sid, tc.sidErr }
			aclFromEntries = func([]windows.EXPLICIT_ACCESS, *windows.ACL) (*windows.ACL, error) {
				return &windows.ACL{}, tc.aclErr
			}
			setNamedSecurityInfo = func(
				string,
				windows.SE_OBJECT_TYPE,
				windows.SECURITY_INFORMATION,
				*windows.SID,
				*windows.SID,
				*windows.ACL,
				*windows.ACL,
			) error {
				return tc.setErr
			}

			err = OwnerOnly("capability")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
