//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/peg/rampart/internal/securefile"
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
	secureOwnerOnlyFile  = securefile.OwnerOnly
)

// secureFilePermissions delegates secret-file hardening to the shared
// cross-platform implementation. Directory repair below remains intentionally
// CLI-specific because it recognizes one legacy Rampart ACL shape.
func secureFilePermissions(path string) error {
	return secureOwnerOnlyFile(path)
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
		// Stat can succeed on Windows even when the directory denies traversal.
		// Opening the directory is a read-only access probe and avoids creating
		// an antivirus-visible temp file on every short-lived hook invocation.
		if err := probeDirectoryAccess(path); err == nil {
			return nil
		} else if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("check Rampart directory access: %w", err)
		}
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

func probeDirectoryAccess(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return dir.Close()
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
