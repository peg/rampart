// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

//go:build windows

// Package securefile applies platform-native owner-only access controls to
// files containing Rampart secrets or authorization state.
package securefile

import (
	"fmt"
	"os"

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

// OwnerOnly replaces the file DACL with a protected current-user-only DACL.
// The SID comes directly from the process token, avoiding account-name lookup
// failures on domain and AzureAD machines.
func OwnerOnly(path string) error {
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

// SingleLink rejects shared file records before a private mutable file is changed.
func SingleLink(file *os.File) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("private file must have exactly one hard link")
	}
	return nil
}
