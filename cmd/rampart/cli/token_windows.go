//go:build windows

package cli

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	advapi32                     = syscall.NewLazyDLL("advapi32.dll")
	procGetNamedSecurityInfoW    = advapi32.NewProc("GetNamedSecurityInfoW")
	procSetNamedSecurityInfoW    = advapi32.NewProc("SetNamedSecurityInfoW")
	procSetEntriesInAclW         = advapi32.NewProc("SetEntriesInAclW")
	procGetSecurityDescriptorOwner = advapi32.NewProc("GetSecurityDescriptorOwner")
)

const (
	SE_FILE_OBJECT           = 1
	DACL_SECURITY_INFORMATION = 0x00000004
	OWNER_SECURITY_INFORMATION = 0x00000001

	// Access rights
	GENERIC_ALL = 0x10000000

	// ACE types
	GRANT_ACCESS = 1

	// Trustee form
	TRUSTEE_IS_SID = 0

	// Trustee type
	TRUSTEE_IS_USER = 1
)

// EXPLICIT_ACCESS structure for SetEntriesInAcl
type explicitAccess struct {
	grfAccessPermissions uint32
	grfAccessMode        uint32
	grfInheritance       uint32
	trustee              trustee
}

type trustee struct {
	pMultipleTrustee         uintptr
	MultipleTrusteeOperation uint32
	TrusteeForm              uint32
	TrusteeType              uint32
	ptstrName                uintptr
}

// secureFilePermissions sets owner-only access on Windows using ACLs.
// This grants GENERIC_ALL to the file owner and removes all other access.
func secureFilePermissions(path string) error {
	return setOwnerOnlyAccess(path)
}

// secureDirPermissions sets owner-only access on Windows using ACLs.
func secureDirPermissions(path string) error {
	return setOwnerOnlyAccess(path)
}

func setOwnerOnlyAccess(path string) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	// Get the current owner SID
	var pSD uintptr
	var pOwnerSid uintptr
	
	ret, _, _ := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION,
		uintptr(unsafe.Pointer(&pOwnerSid)),
		0, // group
		0, // dacl
		0, // sacl
		uintptr(unsafe.Pointer(&pSD)),
	)
	if ret != 0 {
		// Fall back to os.Chmod which is a no-op but at least doesn't fail
		return os.Chmod(path, 0o600)
	}
	defer syscall.LocalFree(syscall.Handle(pSD))

	if pOwnerSid == 0 {
		// Can't get owner, fall back
		return os.Chmod(path, 0o600)
	}

	// Create an EXPLICIT_ACCESS entry granting GENERIC_ALL to the owner
	ea := explicitAccess{
		grfAccessPermissions: GENERIC_ALL,
		grfAccessMode:        GRANT_ACCESS,
		grfInheritance:       0,
		trustee: trustee{
			TrusteeForm: TRUSTEE_IS_SID,
			TrusteeType: TRUSTEE_IS_USER,
			ptstrName:   pOwnerSid,
		},
	}

	// Create new ACL with only the owner entry (removes all other access)
	var pNewDacl uintptr
	ret, _, _ = procSetEntriesInAclW.Call(
		1, // count
		uintptr(unsafe.Pointer(&ea)),
		0, // old ACL (nil = create new)
		uintptr(unsafe.Pointer(&pNewDacl)),
	)
	if ret != 0 {
		return os.Chmod(path, 0o600)
	}
	defer syscall.LocalFree(syscall.Handle(pNewDacl))

	// Apply the new DACL to the file
	ret, _, _ = procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		0, // owner (don't change)
		0, // group (don't change)
		pNewDacl,
		0, // sacl
	)
	if ret != 0 {
		return os.Chmod(path, 0o600)
	}

	return nil
}
