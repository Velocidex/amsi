// Copyright 2018 Gareth Jensen. All Rights Reserved.
// Use of this source code is goverened by an MIT
// license that can be found in the LICENSE file.

package amsi

import (
    "errors"
    "os"
    "runtime"
    "syscall"
    "unsafe"
)

// Context is the application's handle to AMSI's scan API. Can request API
// sessions for scanning files through the context.
type Context uintptr
var context *Context

// Initialize the AMSI API. Automatically uses the name of the calling 
// application to initialize. Returns the AMSI context for calling API 
// functions.
func Initialize() (error) {
    runtime.LockOSThread()
    
    context = new(Context);
    r1, r2, _ := amsiInitialize.Call(
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(os.Args[0]))),
        uintptr(unsafe.Pointer(&context)))
    if r1 != 0 || r2 != 0 { 
        return errors.New("Failed to initialize") 
    }
    return nil
}

// Uninitialize the AMSI API. Removes the instance opened by Initialize.
func Uninitialize() {
    runtime.UnlockOSThread()
    amsiUninitialize.Call(uintptr(unsafe.Pointer(context)))
}
