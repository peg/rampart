//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	currentProcessUserSID = func() (*windows.SID, error) {
		tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return nil, err
		}
		return tokenUser.User.Sid, nil
	}
	aclFromEntries       = windows.ACLFromEntries
	getNamedSecurityInfo = windows.GetNamedSecurityInfo
	setNamedSecurityInfo = windows.SetNamedSecurityInfo
)

// secureFilePermissions replaces the file DACL atomically with a protected
// owner-only DACL. Reading the SID from the process token avoids account-name
// resolution, which may be unavailable on domain and AzureAD machines.
func secureFilePermissions(path string) error {
	sid, err := currentProcessUserSID()
	if err != nil {
		return fmt.Errorf("get current process user SID: %w", err)
	}

	acl, err := aclFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("build owner-only DACL: %w", err)
	}

	if err := setNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("set owner-only DACL: %w", err)
	}

	return nil
}

// secureDirPermissions deliberately leaves the shared Rampart data directory
// ACL unchanged. Sensitive files apply their own protected DACLs.
func secureDirPermissions(string) error {
	return nil
}

// ensureRampartDirAccessible repairs only the legacy Rampart lockout shape:
// an existing directory owned by this process user, protected from inherited
// ACLs, and currently unwritable. Accessible or deliberately customized ACLs
// are never modified.
func ensureRampartDirAccessible(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("inspect Rampart directory: %w", err)
		}
	} else {
		if !info.IsDir() {
			return fmt.Errorf("Rampart data path is not a directory: %s", path)
		}
		// The affected legacy ACL denies even directory metadata access. Avoid
		// creating a probe file on every short-lived hook invocation when Stat
		// proves this is not that lockout shape.
		return nil
	}

	sid, err := currentProcessUserSID()
	if err != nil {
		return fmt.Errorf("get current process user SID: %w", err)
	}

	descriptor, err := getNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read directory DACL: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read directory owner: %w", err)
	}
	if owner == nil || !owner.Equals(sid) {
		return fmt.Errorf("refusing to repair Rampart directory not owned by the current process user")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read directory DACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("refusing to repair an inaccessible Rampart directory without the legacy protected DACL")
	}
	existingACL, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("extract directory DACL: %w", err)
	}
	hasCurrentSIDEntry, err := aclContainsExplicitSID(existingACL, sid)
	if err != nil {
		return fmt.Errorf("inspect directory DACL entries: %w", err)
	}
	if hasCurrentSIDEntry {
		return fmt.Errorf("refusing to repair a Rampart directory with an existing current-user ACL entry")
	}

	acl, err := aclFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		},
	}, existingACL)
	if err != nil {
		return fmt.Errorf("build recoverable directory DACL: %w", err)
	}

	if err := setNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("set recoverable directory DACL: %w", err)
	}

	if err := probeDirectoryWrite(path); err != nil {
		return fmt.Errorf("verify repaired Rampart directory access: %w", err)
	}
	return nil
}

func aclContainsExplicitSID(acl *windows.ACL, sid *windows.SID) (bool, error) {
	if acl == nil {
		return false, nil
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return false, err
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE &&
			ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if aceSID.Equals(sid) {
			return true, nil
		}
	}
	return false, nil
}

func probeDirectoryWrite(path string) error {
	f, err := os.CreateTemp(path, ".rampart-access-*")
	if err != nil {
		return err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Remove(name)
}
