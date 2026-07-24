//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func withWindowsACLStubs(t *testing.T) {
	t.Helper()
	originalCurrentProcessUserSID := currentProcessUserSID
	originalACLFromEntries := aclFromEntries
	originalGetNamedSecurityInfo := getNamedSecurityInfo
	originalSetNamedSecurityInfo := setNamedSecurityInfo
	t.Cleanup(func() {
		currentProcessUserSID = originalCurrentProcessUserSID
		aclFromEntries = originalACLFromEntries
		getNamedSecurityInfo = originalGetNamedSecurityInfo
		setNamedSecurityInfo = originalSetNamedSecurityInfo
	})
}

func TestSecureFilePermissionsUsesProcessSIDAndProtectedDACL(t *testing.T) {
	withWindowsACLStubs(t)

	sid, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	wantACL := &windows.ACL{}

	currentProcessUserSID = func() (*windows.SID, error) {
		return sid, nil
	}
	aclFromEntries = func(entries []windows.EXPLICIT_ACCESS, merged *windows.ACL) (*windows.ACL, error) {
		if merged != nil {
			t.Fatal("owner-only ACL must not merge inherited or existing entries")
		}
		if len(entries) != 1 {
			t.Fatalf("got %d ACL entries, want 1", len(entries))
		}
		entry := entries[0]
		if entry.AccessPermissions != windows.GENERIC_ALL {
			t.Errorf("permissions = %#x, want GENERIC_ALL", entry.AccessPermissions)
		}
		if entry.AccessMode != windows.SET_ACCESS {
			t.Errorf("access mode = %d, want SET_ACCESS", entry.AccessMode)
		}
		if entry.Inheritance != windows.NO_INHERITANCE {
			t.Errorf("inheritance = %#x, want NO_INHERITANCE", entry.Inheritance)
		}
		if entry.Trustee.TrusteeForm != windows.TRUSTEE_IS_SID {
			t.Errorf("trustee form = %d, want TRUSTEE_IS_SID", entry.Trustee.TrusteeForm)
		}
		if entry.Trustee.TrusteeType != windows.TRUSTEE_IS_USER {
			t.Errorf("trustee type = %d, want TRUSTEE_IS_USER", entry.Trustee.TrusteeType)
		}
		if entry.Trustee.TrusteeValue != windows.TrusteeValueFromSID(sid) {
			t.Error("ACL trustee does not use the current process SID")
		}
		return wantACL, nil
	}

	var setCalled bool
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
		if path != `C:\Users\alice\.rampart\.token-123` {
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
		if owner != nil || group != nil || sacl != nil {
			t.Error("unexpected owner, group, or SACL change")
		}
		if dacl != wantACL {
			t.Error("SetNamedSecurityInfo did not receive the owner-only DACL")
		}
		return nil
	}

	if err := secureFilePermissions(`C:\Users\alice\.rampart\.token-123`); err != nil {
		t.Fatalf("secureFilePermissions: %v", err)
	}
	if !setCalled {
		t.Fatal("SetNamedSecurityInfo was not called")
	}
}

func TestSecureFilePermissionsFailsClosed(t *testing.T) {
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
			currentProcessUserSID = func() (*windows.SID, error) {
				return sid, tc.sidErr
			}
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

			err = secureFilePermissions("token")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestSecureFilePermissionsAppliesOwnerOnlyDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureFilePermissions(path); err != nil {
		t.Fatalf("secureFilePermissions: %v", err)
	}

	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("read security descriptor control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("token DACL still permits inherited access")
	}

	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("read token DACL: %v", err)
	}
	if dacl == nil {
		t.Fatal("token has no DACL")
	}
	if dacl.AceCount != 1 {
		t.Fatalf("token DACL has %d entries, want 1", dacl.AceCount)
	}

	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatalf("GetAce: %v", err)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	processSID, err := currentProcessUserSID()
	if err != nil {
		t.Fatalf("currentProcessUserSID: %v", err)
	}
	if !aceSID.Equals(processSID) {
		t.Fatalf("token DACL SID = %s, want current process SID %s", aceSID, processSID)
	}
}

func TestSecureDirPermissionsDoesNotChangeSharedDirectoryACL(t *testing.T) {
	withWindowsACLStubs(t)

	currentProcessUserSID = func() (*windows.SID, error) {
		t.Fatal("secureDirPermissions must not look up the user SID")
		return nil, nil
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
		t.Fatal("secureDirPermissions must not alter the shared directory DACL")
		return nil
	}

	if err := secureDirPermissions(`C:\Users\alice\.rampart`); err != nil {
		t.Fatalf("secureDirPermissions: %v", err)
	}
}

func TestEnsureRampartDirAccessibleLeavesAccessibleProtectedACLAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".rampart")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	processSID, err := currentProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(processSID),
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	if err := ensureRampartDirAccessible(dir); err != nil {
		t.Fatalf("ensureRampartDirAccessible: %v", err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("accessible custom protected DACL was unexpectedly changed")
	}
}

func TestServePreRunRepairsLegacyDirectoryLockout(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	dir := filepath.Join(home, ".rampart")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockLegacyRampartDir(t, dir)

	if err := probeDirectoryWrite(dir); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("legacy lock probe error = %v, want access denied", err)
	}

	cmd := newServeCmd(&rootOptions{configPath: "rampart.yaml"}, nil)
	if cmd.PreRunE == nil {
		t.Fatal("serve has no early Rampart directory recovery hook")
	}
	if err := cmd.PreRunE(cmd, nil); err != nil {
		t.Fatalf("serve pre-run recovery: %v", err)
	}
	if err := probeDirectoryWrite(dir); err != nil {
		t.Fatalf("repaired directory is not writable: %v", err)
	}

	descriptor, err := windows.GetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED != 0 {
		t.Fatal("legacy directory DACL is still protected from inheritance")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	processSID, err := currentProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if !aclContainsSID(t, dacl, processSID) {
		t.Fatalf("repaired directory DACL does not contain process SID %s", processSID)
	}
}

func TestHookRepairsLegacyDirectoryBeforeCommandWork(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	dir := filepath.Join(home, ".rampart")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockLegacyRampartDir(t, dir)

	cmd := newHookCmd(&rootOptions{configPath: "rampart.yaml"})
	cmd.SetArgs([]string{"--mode", "invalid"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "invalid mode") {
		t.Fatalf("hook error = %v, want invalid mode after recovery", err)
	}
	if err := probeDirectoryWrite(dir); err != nil {
		t.Fatalf("hook did not repair legacy directory before command work: %v", err)
	}
}

func lockLegacyRampartDir(t *testing.T, dir string) {
	t.Helper()
	processSID, err := currentProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	recoveryACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(processSID),
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = windows.SetNamedSecurityInfo(
			dir,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			nil,
			nil,
			recoveryACL,
			nil,
		)
	})

	unrelatedSID, err := windows.StringToSid("S-1-5-19")
	if err != nil {
		t.Fatal(err)
	}
	lockedACL, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(unrelatedSID),
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		processSID,
		nil,
		lockedACL,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func aclContainsSID(t *testing.T, acl *windows.ACL, want *windows.SID) bool {
	t.Helper()
	if acl == nil {
		return false
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatalf("GetAce(%d): %v", i, err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(want) {
			return true
		}
	}
	return false
}
