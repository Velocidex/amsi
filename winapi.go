// Copyright 2018 Gareth Jensen. All Rights Reserved.
// Use of this source code is goverened by an MIT
// license that can be found in the LICENSE file.

package amsi

import "syscall"

// Entry points for AMSI through proc invoke
var amsi *syscall.DLL
var amsiInitialize *syscall.Proc
var amsiUninitialize *syscall.Proc
var amsiOpenSession *syscall.Proc
var amsiCloseSession *syscall.Proc
var amsiScanBuffer *syscall.Proc
var amsiScanString *syscall.Proc

func init() {
	amsiMaybe, err := syscall.LoadDLL("amsi.dll")
	if err == nil {
		amsi = amsiMaybe
		amsiInitialize = amsi.MustFindProc("AmsiInitialize")
		amsiUninitialize = amsi.MustFindProc("AmsiUninitialize")
		amsiOpenSession = amsi.MustFindProc("AmsiOpenSession")
		amsiCloseSession = amsi.MustFindProc("AmsiCloseSession")
		amsiScanBuffer = amsi.MustFindProc("AmsiScanBuffer")
		amsiScanString = amsi.MustFindProc("AmsiScanString")
	}
}

// ScanResult is an enumeration which specifies the types of results returned
// by scans from AMSI.
type ScanResult int

// Enum values for ScanResult
const (
	ResultClean               ScanResult = 0
	ResultNotDetected         ScanResult = 1
	CannotInitializeAmsi      ScanResult = 2
	ResultBlockedByAdminStart ScanResult = 16384
	ResultBlockedByAdminEnd   ScanResult = 20479
	ResultDetected            ScanResult = 32768
)
