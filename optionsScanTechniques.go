package nmap

import "fmt"

// WithSYNScan sets the scan technique to use SYN packets over TCP.
// This is the default method, as it is fast, stealthy and not
// hampered by restrictive firewalls.
func WithSYNScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sS")
	}
}

// WithConnectScan sets the scan technique to use TCP connections.
// This is the default method used when a user does not have raw
// packet privileges. Target machines are likely to log these
// connections.
func WithConnectScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sT")
	}
}

// WithACKScan sets the scan technique to use ACK packets over TCP.
// This scan is unable to determine if a port is open.
// When scanning unfiltered systems, open and closed ports will both
// return a RST packet.
// Nmap then labels them as unfiltered, meaning that they are reachable
// by the ACK packet, but whether they are open or closed is undetermined.
func WithACKScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sA")
	}
}

// WithWindowScan sets the scan technique to use ACK packets over TCP and
// examining the TCP window field of the RST packets returned.
// Window scan is exactly the same as ACK scan except that it exploits
// an implementation detail of certain systems to differentiate open ports
// from closed ones, rather than always printing unfiltered when a RST
// is returned.
func WithWindowScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sW")
	}
}

// WithMaimonScan sends the same packets as NULL, FIN, and Xmas scans,
// except that the probe is FIN/ACK. Many BSD-derived systems will drop
// these packets if the port is open.
func WithMaimonScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sM")
	}
}

// WithUDPScan sets the scan technique to use UDP packets.
// It can be combined with a TCP scan type such as SYN scan
// to check both protocols during the same run.
// UDP scanning is generally slower than TCP, but should not
// be ignored.
func WithUDPScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sU")
	}
}

// WithTCPNullScan sets the scan technique to use TCP null packets.
// (TCP flag header is 0). This scan method can be used to exploit
// a loophole in the TCP RFC.
// If an RST packet is received, the port is considered closed,
// while no response means it is open|filtered.
func WithTCPNullScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sN")
	}
}

// WithTCPFINScan sets the scan technique to use TCP packets with
// the FIN flag set.
// This scan method can be used to exploit a loophole in the TCP RFC.
// If an RST packet is received, the port is considered closed,
// while no response means it is open|filtered.
func WithTCPFINScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sF")
	}
}

// WithTCPXmasScan sets the scan technique to use TCP packets with
// the FIN, PSH and URG flags set.
// This scan method can be used to exploit a loophole in the TCP RFC.
// If an RST packet is received, the port is considered closed,
// while no response means it is open|filtered.
func WithTCPXmasScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sX")
	}
}

// TCPFlag represents a TCP flag.
type TCPFlag int

// Flag enumerations.
const (
	FlagNULL TCPFlag = 0
	FlagFIN  TCPFlag = 1
	FlagSYN  TCPFlag = 2
	FlagRST  TCPFlag = 4
	FlagPSH  TCPFlag = 8
	FlagACK  TCPFlag = 16
	FlagURG  TCPFlag = 32
	FlagECE  TCPFlag = 64
	FlagCWR  TCPFlag = 128
	FlagNS   TCPFlag = 256
)

// WithTCPScanFlags sets the scan technique to use custom TCP flags.
func WithTCPScanFlags(flags ...TCPFlag) Option {
	var total int
	for _, flag := range flags {
		total += int(flag)
	}

	return func(s *Scanner) {
		s.args = append(s.args, "--scanflags")
		s.args = append(s.args, fmt.Sprintf("%x", total))
	}
}

// WithIdleScan sets the scan technique to use a zombie host to
// allow for a truly blind TCP port scan of the target.
// Besides being extraordinarily stealthy (due to its blind nature),
// this scan type permits mapping out IP-based trust relationships
// between machines.
func WithIdleScan(zombieHost string, probePort int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sI")

		if probePort != 0 {
			s.args = append(s.args, fmt.Sprintf("%s:%d", zombieHost, probePort))
		} else {
			s.args = append(s.args, zombieHost)
		}
	}
}

// WithSCTPInitScan sets the scan technique to use SCTP packets
// containing an INIT chunk.
// It can be performed quickly, scanning thousands of ports per
// second on a fast network not hampered by restrictive firewalls.
// Like SYN scan, INIT scan is relatively unobtrusive and stealthy,
// since it never completes SCTP associations.
func WithSCTPInitScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sY")
	}
}

// WithSCTPCookieEchoScan sets the scan technique to use SCTP packets
// containing a COOKIE-ECHO chunk.
// The advantage of this scan type is that it is not as obvious a port
// scan than an INIT scan. Also, there may be non-stateful firewall
// rulesets blocking INIT chunks, but not COOKIE ECHO chunks.
func WithSCTPCookieEchoScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sZ")
	}
}

// WithIPProtocolScan sets the scan technique to use the IP protocol.
// IP protocol scan allows you to determine which IP protocols
// (TCP, ICMP, IGMP, etc.) are supported by target machines. This isn't
// technically a port scan, since it cycles through IP protocol numbers
// rather than TCP or UDP port numbers.
func WithIPProtocolScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sO")
	}
}

// WithFTPBounceScan sets the scan technique to use the an FTP relay host.
// It takes an argument of the form "<username>:<password>@<server>:<port>. <Server>".
// You may omit <username>:<password>, in which case anonymous login credentials
// (user: anonymous password:-wwwuser@) are used.
// The port number (and preceding colon) may be omitted as well, in which case the
// default FTP port (21) on <server> is used.
func WithFTPBounceScan(FTPRelayHost string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-b")
		s.args = append(s.args, FTPRelayHost)
	}
}
