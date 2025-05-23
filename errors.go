package nmap

import (
	"errors"
)

var (
	// ErrNmapNotInstalled means that upon trying to manually locate nmap in the user's path,
	// it was not found. Either use the WithBinaryPath method to set it manually, or make sure that
	// the nmap binary is present in the user's $PATH.
	ErrNmapNotInstalled = errors.New("nmap binary was not found")

	// ErrScanTimeout means that the provided context timeout triggered done before the scanner finished its scan.
	// This error will *not* be returned if a scan timeout was configured using Nmap arguments, since Nmap would
	// gracefully shut down it's scanning and return some results in that case.
	ErrScanTimeout = errors.New("nmap scan timed out")

	// ErrScanInterrupt means that the scan was interrupted before the scanner finished its scan.
	// Reasons for this error might be sigint or a cancelled context.
	ErrScanInterrupt = errors.New("nmap scan interrupted")

	// ErrMallocFailed means that nmap crashed due to insufficient memory, which may happen on large target networks.
	ErrMallocFailed = errors.New("malloc failed, probably out of space")

	// ErrParseOutput means that nmap's output was not parsed successfully.
	ErrParseOutput = errors.New("unable to parse nmap output, see warnings for details")

	// ErrRequiresRoot means that a feature (e.g. OS detection) requires root privileges
	ErrRequiresRoot = errors.New("this feature requires root privileges")

	// ErrResolveName means that Nmap could not resolve a name.
	ErrResolveName = errors.New("nmap could not resolve a name")
)
