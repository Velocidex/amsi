// Copyright 2018 Gareth Jensen. All Rights Reserved.
// Use of this source code is goverened by an MIT
// license that can be found in the LICENSE file.

package amsi

import (
	"os"
	"syscall"
	"unsafe"
)

// Session for scanning multiple files.
type Session uintptr

// OpenSession opens an AMSI session for requesting scans on one or multiple
// files. Returns a session object for requesting scans.
func OpenSession() *Session {
	if amsiOpenSession == nil {
		return nil
	}
	session := new(Session)
	amsiOpenSession.Call(
		uintptr(unsafe.Pointer(context)),
		uintptr(unsafe.Pointer(&session)))
	return session
}

// CloseSession from the initialized context's open session function.
func CloseSession(session *Session) {
	if amsiCloseSession == nil {
		return
	}
	amsiCloseSession.Call(
		uintptr(unsafe.Pointer(context)),
		uintptr(unsafe.Pointer(session)))
}

// ScanString scans a string for malware. Returns the scan result.
func (session *Session) ScanString(str string) ScanResult {
	if amsiScanString == nil {
		return CannotInitializeAmsi
	}
	var result ScanResult
	utf16Str, err := syscall.UTF16PtrFromString(str)
	if err != nil {
		panic(err)
	}
	utf16Name, err := syscall.UTF16PtrFromString(os.Args[0])
	if err != nil {
		panic(err)
	}
	amsiScanString.Call(
		uintptr(unsafe.Pointer(context)),
		uintptr(unsafe.Pointer(utf16Str)),
		uintptr(unsafe.Pointer(utf16Name)),
		uintptr(unsafe.Pointer(session)),
		uintptr(unsafe.Pointer(&result)))
	return result
}

// ScanBuffer scans a buffer of content for malware. Returns the scan result.
func (session *Session) ScanBuffer(fileContent []byte) ScanResult {
	if amsiScanBuffer == nil {
		return CannotInitializeAmsi
	}
	var result ScanResult
	utf16Name, err := syscall.UTF16PtrFromString(os.Args[0])
	if err != nil {
		panic(err)
	}
	amsiScanBuffer.Call(
		uintptr(unsafe.Pointer(context)),
		uintptr(unsafe.Pointer(&fileContent[0])),
		uintptr(uint64(len(fileContent))),
		uintptr(unsafe.Pointer(utf16Name)),
		uintptr(unsafe.Pointer(session)),
		uintptr(unsafe.Pointer(&result)))
	return result
}
