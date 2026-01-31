package nmap

import (
	"fmt"
	"strings"
)

// WithSYNScan sets the scan technique to use SYN packets over TCP.
// This is the default method, as it is fast, stealthy and not
// hampered by restrictive firewalls.
func WithSYNScan() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sS")
		return nil
	}
}

// WithConnectScan sets the scan technique to use TCP connections.
// This is the default method used when a user does not have raw
// packet privileges. Target machines are likely to log these
// connections.
func WithConnectScan() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sT")
		return nil
	}
}

// WithACKScan sets the scan technique to use ACK packets over TCP.
// This scan is unable to determine if a port is open.
// When scanning unfiltered systems, open and closed ports both
// return an RST packet.
// Nmap then labels them as unfiltered, meaning that they are reachable
// by the ACK packet, but whether they are open or closed is undetermined.
func WithACKScan() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sA")
		return nil
	}
}

// WithWindowScan sets the scan technique to use ACK packets over TCP and
// examining the TCP window field of the RST packets returned.
// Window scan is exactly the same as ACK scan except that it exploits
// an implementation detail of certain systems to differentiate open ports
// from closed ones, rather than always printing unfiltered when a RST
// is returned.
func WithWindowScan() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sW")
		return nil
	}
}

// WithMaimonScan sends the same packets as NULL, FIN, and Xmas scans,
// except that the probe is FIN/ACK. Many BSD-derived systems drop
// these packets if the port is open.
func WithMaimonScan() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sM")
		return nil
	}
}

// WithUDPScan sets the scan technique to use UDP packets.
// It can be combined with a TCP scan type such as SYN scan
// to check both protocols during the same run.
// UDP scanning is generally slower than TCP, but should not
// be ignored.
//
// NOTE: UDP scans might require elevated privileges.
func WithUDPScan() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sU")
		return nil
	}
}

// WithTCPNullScan sets the scan technique to use TCP null packets.
// (TCP flag header is 0). This scan method can be used to exploit
// a loophole in the TCP RFC.
// If an RST packet is received, the port is considered closed,
// while no response means it is open|filtered.
func WithTCPNullScan() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sN")
		return nil
	}
}

// WithTCPFINScan sets the scan technique to use TCP packets with
// the FIN flag set.
// This scan method can be used to exploit a loophole in the TCP RFC.
// If an RST packet is received, the port is considered closed,
// while no response means it is open|filtered.
func WithTCPFINScan() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sF")
		return nil
	}
}

// WithTCPXmasScan sets the scan technique to use TCP packets with
// the FIN, PSH and URG flags set.
// This scan method can be used to exploit a loophole in the TCP RFC.
// If an RST packet is received, the port is considered closed,
// while no response means it is open|filtered.
func WithTCPXmasScan() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sX")
		return nil
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
//
// NOTE: Nmap supports specifying TCP scan flags either as a decimal value or as a
// string (e.g. "SYNACK"). However, the decimal form is limited to 0–255 because
// it maps strictly to the 8-bit TCP flags field (FIN through CWR). The NS flag
// does not live in this byte; it occupies a separate bit in the TCP reserved
// field and therefore cannot be represented in a single 8-bit integer.
//
// As a result, any flag combination involving NS (and, more generally, full
// TCP control-bit manipulation) can only be expressed using the string form.
// We therefore always emit string-based scan flags to ensure correctness and
// full feature coverage.
func WithTCPScanFlags(flags ...TCPFlag) Option {
	var flag strings.Builder
	for _, v := range flags {
		switch v {
		case FlagNULL:
			continue
		case FlagFIN:
			flag.WriteString("FIN")
		case FlagSYN:
			flag.WriteString("SYN")
		case FlagRST:
			flag.WriteString("RST")
		case FlagPSH:
			flag.WriteString("PSH")
		case FlagACK:
			flag.WriteString("ACK")
		case FlagURG:
			flag.WriteString("URG")
		case FlagECE:
			flag.WriteString("ECE")
		case FlagCWR:
			flag.WriteString("CWR")
		case FlagNS:
			flag.WriteString("NS")
		}
	}

	return func(s *Scanner) error {
		s.args = append(s.args, "--scanflags="+flag.String())
		return nil
	}
}

// WithIdleScan sets the scan technique to use a zombie host to
// allow for a truly blind TCP port scan of the target.
// Besides being extraordinarily stealthy (due to its blind nature),
// this scan type permits mapping out IP-based trust relationships
// between machines.
func WithIdleScan(zombieHost string, probePort int) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sI")

		if probePort != 0 {
			s.args = append(s.args, fmt.Sprintf("%s:%d", zombieHost, probePort))
			return nil
		}

		s.args = append(s.args, zombieHost)
		return nil
	}
}

// WithSCTPInitScan sets the scan technique to use SCTP packets
// containing an INIT chunk.
// It can be performed quickly, scanning thousands of ports per
// second on a fast network not hampered by restrictive firewalls.
// Like SYN scan, INIT scan is relatively unobtrusive and stealthy,
// since it never completes SCTP associations.
func WithSCTPInitScan() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sY")
		return nil
	}
}

// WithSCTPCookieEchoScan sets the scan technique to use SCTP packets
// containing a COOKIE-ECHO chunk.
// The advantage of this scan type is that it is not as obvious a port
// scan than an INIT scan. Also, there may be non-stateful firewall
// rulesets blocking INIT chunks, but not COOKIE ECHO chunks.
func WithSCTPCookieEchoScan() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sZ")
		return nil
	}
}

// WithIPProtocolScan sets the scan technique to use the IP protocol.
// IP protocol scan allows you to determine which IP protocols
// (TCP, ICMP, IGMP, etc.) are supported by target machines. This isn't
// technically a port scan, since it cycles through IP protocol numbers
// rather than TCP or UDP port numbers.
func WithIPProtocolScan() Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-sO")
		return nil
	}
}

// WithFTPBounceScan sets the scan technique to use an FTP relay host.
// It takes an argument of the form "<username>:<password>@<server>:<port>. <Server>".
// You may omit <username>:<password>, in which case anonymous login credentials
// (user: anonymous password:-wwwuser@) are used.
// The port number (and preceding colon) may be omitted as well, in which case the
// default FTP port (21) on <server> is used.
func WithFTPBounceScan(ftpRelayHost string) Option {
	return func(s *Scanner) error {
		s.args = append(s.args, "-b", ftpRelayHost)
		return nil
	}
}
