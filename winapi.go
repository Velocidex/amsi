// Copyright 2018 Gareth Jensen. All Rights Reserved.
// Use of this source code is goverened by an MIT
// license that can be found in the LICENSE file.

package amsi

import (
	"golang.org/x/sys/windows"
)

// Entry points for AMSI through proc invoke
var (
	amsi             = windows.NewLazySystemDLL("amsi.dll")
	amsiInitialize   = amsi.NewProc("AmsiInitialize")
	amsiUninitialize = amsi.NewProc("AmsiUninitialize")
	amsiOpenSession  = amsi.NewProc("AmsiOpenSession")
	amsiCloseSession = amsi.NewProc("AmsiCloseSession")
	amsiScanBuffer   = amsi.NewProc("AmsiScanBuffer")
	amsiScanString   = amsi.NewProc("AmsiScanString")
)

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
