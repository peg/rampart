//go:build windows

package cli

import (
	"fmt"

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
// ACL unchanged. Only the token file contains a secret that needs a protected
// owner-only DACL.
func secureDirPermissions(string) error {
	return nil
}
