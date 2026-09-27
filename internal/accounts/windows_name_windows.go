//go:build windows

package accounts

import "os"

func getComputerName() string { return os.Getenv("COMPUTERNAME") }
