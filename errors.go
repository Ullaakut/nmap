package nmap

import (
	"errors"
)

var (
	// ErrNmapNotInstalled means that upon trying to manually locate nmap in the user's path,
	// it was not found. Either use the WithBinaryPath method to set it manually, or make sure that
	// the nmap binary is present in the user's $PATH.
	ErrNmapNotInstalled = errors.New("nmap binary was not found")

	// ErrScanTimeout means that the provided context was done before the scanner finished its scan.
	ErrScanTimeout = errors.New("nmap scan timed out")

	// ErrScanTimeout means that the provided context was done before the scanner finished its scan.
	ErrParseOutput = errors.New("nmap output broken, see warnings for details")

	// ErrExcludeList means that Nmap could not resolve host from exclude list and terminated.
	ErrExcludeList = errors.New("nmap could not resolve exclude list")
)
