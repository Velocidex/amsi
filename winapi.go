// Copyright 2018 Gareth Jensen. All Rights Reserved.
// Use of this source code is goverened by an MIT
// license that can be found in the LICENSE file.

package amsi

import "syscall"

// Entry points for AMSI through proc invoke
var amsi = syscall.MustLoadDLL("amsi.dll")
var amsiInitialize      = amsi.MustFindProc("AmsiInitialize")
var amsiUninitialize    = amsi.MustFindProc("AmsiUninitialize")
var amsiOpenSession     = amsi.MustFindProc("AmsiOpenSession")
var amsiCloseSession    = amsi.MustFindProc("AmsiCloseSession")
var amsiScanBuffer      = amsi.MustFindProc("AmsiScanBuffer")
var amsiScanString      = amsi.MustFindProc("AmsiScanString")

// ScanResult is an enumeration which specifies the types of results returned
// by scans from AMSI.
type ScanResult int

// Enum values for ScanResult
const (
    ResultClean               ScanResult = iota
    ResultNotDetected         ScanResult = 1
    ResultBlockedByAdminStart ScanResult = 16384
    ResultBlockedByAdminEnd   ScanResult = 20479
    ResultDetected            ScanResult = 32768
)
