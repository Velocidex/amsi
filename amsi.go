// Copyright 2018 Gareth Jensen. All Rights Reserved.
// Use of this source code is goverened by an MIT
// license that can be found in the LICENSE file.

// Package amsi encapsulates Microsoft's Antimalware Scan Interface for
// scanning files from Golang for any Windows 10 or Windows Server 2016 
// system. Supports the Azure extension for integrating Microsoft Antimalware
// Protection in Windows VMs. Since the interface itself is generic, may also
// support scanning via the primary anti-virus present on the machine.
package amsi
