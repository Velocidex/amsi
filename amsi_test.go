// Copyright 2018 Gareth Jensen. All Rights Reserved.
// Use of this source code is goverened by an MIT
// license that can be found in the LICENSE file.

package amsi

import "testing"

// TestInitialize will load the AMSI DLL and map entry points to procs, then
// initialize and deallocate the AMSI scan interface through syscalls. Fails
// if the system doesn't support AMSI's scan interface.
func TestInitialize(t *testing.T) {
    err := Initialize()
    if err != nil { t.Fail() }
    Uninitialize()
}

// TestSession opens and closes a session from an initialized AMSI Context.
// Fails if the session cannot be opened.
func TestSession(t *testing.T) {
    err := Initialize()
    if err != nil { t.Fail() }
    defer Uninitialize()

    session := OpenSession()
    if session == nil { t.Fail() }
    CloseSession(session)
}

// TestScanString scans strings for viruses. Tests that a non-malicious string
// passes with no threats detected, and the standard anti-virus test string 
// fails with threats were detected.
func TestScanString(t *testing.T) {
    err := Initialize()
    if err != nil { t.Fail() }
    defer Uninitialize()

    session := OpenSession()
    if session == nil { t.Fail() }
    defer CloseSession(session)

    result := session.ScanString("Hello World")
    if result != ResultNotDetected { t.Fail() }

    result = session.ScanString(
        `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
    if result != ResultDetected { t.Fail() }
}

// TestScanBuffer scans a buffer for viruses. Tests that a non-malicious file
// passes with no threats detected, and the standard anti-virus test file 
// fails with threats were detected. 
func TestScanBuffer(t *testing.T) {
    err := Initialize()
    if err != nil { t.Fail() }
    defer Uninitialize()

    session := OpenSession()
    if session == nil { t.Fail() }
    defer CloseSession(session)

    buffer := []byte("Hello World")
    result := session.ScanBuffer(buffer)
    if result != ResultNotDetected { t.Fail() }

    buffer = []byte(
        `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
    result = session.ScanBuffer(buffer)
    if result != ResultDetected { t.Fail() }
}
