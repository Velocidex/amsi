# Microsoft Antimalware Golang API
This package implements a Golang API for Microsoft's Antimalware Scan Interface (AMSI). This package allows Go programs to integrate with any antimalware product present on a Windows 10 or Windows Server 2016 machine. 

## Example
```
package main

import (
    "warry.io/amsi"
)

func main() {
    err := amsi.Initialize()
    if err != nil { panic(err) }
    defer amsi.Uninitialize()

    session := amsi.OpenSession()
    defer amsi.CloseSession(session)
    result := session.ScanString("Hello World")
    if result != amsi.ResultNotDetected {
        panic("Hello world is not a virus")
    } 

    result = session.ScanString(
        `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
    if result != amsi.ResultDetected {
        panic("Test virus string is a \"virus\"")
    } 
}
```
