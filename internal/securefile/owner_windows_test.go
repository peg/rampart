// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build windows

package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestOwnerOnlyFileAppliesDACLToRenamedHandle(t *testing.T) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	processSID := tokenUser.User.Sid
	// Start with a real extra trustee, so a successful no-op cannot pass.
	fixture, err := windows.SecurityDescriptorFromString("D:(A;;FA;;;" + processSID.String() + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	fixtureACL, _, err := fixture.DACL()
	if err != nil {
		t.Fatal(err)
	}
	setFixtureACL := func(path string) {
		t.Helper()
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, fixtureACL, nil); err != nil {
			t.Fatalf("set fixture DACL: %v", err)
		}
		runtime.KeepAlive(fixture)
	}
	readPathDACL := func(path string) *windows.SECURITY_DESCRIPTOR {
		t.Helper()
		descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatalf("read path DACL: %v", err)
		}
		return descriptor
	}

	path := filepath.Join(t.TempDir(), "private")
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	// Permit rename while retaining ordinary read/write access without WRITE_DAC.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	setFixtureACL(path)
	before := readPathDACL(path)
	control, _, err := before.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED != 0 {
		t.Fatal("fixture DACL unexpectedly protected")
	}
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatalf("rename delete-shared open file: %v", err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	setFixtureACL(path)
	replacementBefore := readPathDACL(path).String()
	if replacementBefore == "" {
		t.Fatal("replacement DACL could not be serialized")
	}

	if err := OwnerOnlyFile(file); err != nil {
		t.Fatalf("OwnerOnlyFile: %v", err)
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read open-handle DACL: %v", err)
	}
	control, _, err = descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("open file DACL still permits inherited access")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil || dacl.AceCount != 1 {
		t.Fatalf("open file DACL must have exactly one ACE: %s", descriptor)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
		t.Fatalf("open file ACE must be an explicit non-inheriting allow: %#v", ace.Header)
	}
	// GetAce exposes the variable-length SID at ACCESS_ALLOWED_ACE.SidStart.
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.Equals(processSID) {
		t.Fatal("open file ACE does not name the current process user")
	}
	fullControl := windows.ACCESS_MASK(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE |
		windows.FILE_GENERIC_EXECUTE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER)
	if ace.Mask&windows.GENERIC_ALL == 0 && ace.Mask&fullControl != fullControl {
		t.Fatalf("open file owner lacks full control: mask=%#x", ace.Mask)
	}
	runtime.KeepAlive(descriptor)
	if after := readPathDACL(path).String(); after != replacementBefore {
		t.Fatalf("replacement path DACL changed: before=%s after=%s", replacementBefore, after)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "replacement" {
		t.Fatalf("replacement contents changed: %q, %v", data, err)
	}
}

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
