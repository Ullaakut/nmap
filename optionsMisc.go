package nmap

import "syscall"

// WithIPv6Scanning enables the use of IPv6 scanning.
func WithIPv6Scanning() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-6")
	}
}

// WithAggressiveScan enables the use of aggressive scan options. This has
// the same effect as using WithOSDetection, WithServiceInfo, WithDefaultScript
// and WithTraceRoute at the same time.
// Because script scanning with the default set is considered intrusive, you
// should not use this method against target networks without permission.
func WithAggressiveScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-A")
	}
}

// WithDataDir specifies a custom data directory for nmap to get its
// nmap-service-probes, nmap-services, nmap-protocols, nmap-rpc,
// nmap-mac-prefixes, and nmap-os-db.
func WithDataDir(directoryPath string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--datadir")
		s.args = append(s.args, directoryPath)
	}
}

// WithSendEthernet makes nmap send packets at the raw ethernet (data link)
// layer rather than the higher IP (network) layer. By default, nmap chooses
// the one which is generally best for the platform it is running on.
func WithSendEthernet() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--send-eth")
	}
}

// WithSendIP makes nmap send packets via raw IP sockets rather than sending
// lower level ethernet frames.
func WithSendIP() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--send-ip")
	}
}

// WithPrivileged makes nmap assume that the user is fully privileged.
func WithPrivileged() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--privileged")
	}
}

// WithUnprivileged makes nmap assume that the user lacks raw socket privileges.
func WithUnprivileged() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--unprivileged")
	}
}

// WithNmapOutput makes nmap output standard output to the filename specified.
func WithNmapOutput(outputFileName string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-oN")
		s.args = append(s.args, outputFileName)
	}
}

// WithGrepOutput makes nmap output greppable output to the filename specified.
func WithGrepOutput(outputFileName string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-oG")
		s.args = append(s.args, outputFileName)
	}
}

// WithCustomSysProcAttr allows customizing the *syscall.SysProcAttr on the *exec.Cmd instance
func WithCustomSysProcAttr(f func(*syscall.SysProcAttr)) Option {
	return func(s *Scanner) {
		s.modifySysProcAttr = f
	}
}
