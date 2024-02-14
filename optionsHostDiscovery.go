package nmap

import (
	"fmt"
	"strings"
)

// WithListScan sets the discovery mode to simply list the targets to scan and not scan them.
func WithListScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sL")
	}
}

// WithPingScan sets the discovery mode to simply ping the targets to scan and not scan them.
func WithPingScan() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-sn")
	}
}

// WithSkipHostDiscovery disables host discovery and considers all hosts as online.
func WithSkipHostDiscovery() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-Pn")
	}
}

// WithSYNDiscovery sets the discovery mode to use SYN packets.
// If the portList argument is empty, this will enable SYN discovery
// for all ports. Otherwise, it will be only for the specified ports.
func WithSYNDiscovery(ports ...string) Option {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("-PS%s", portList))
	}
}

// WithACKDiscovery sets the discovery mode to use ACK packets.
// If the portList argument is empty, this will enable ACK discovery
// for all ports. Otherwise, it will be only for the specified ports.
func WithACKDiscovery(ports ...string) Option {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("-PA%s", portList))
	}
}

// WithUDPDiscovery sets the discovery mode to use UDP packets.
// If the portList argument is empty, this will enable UDP discovery
// for all ports. Otherwise, it will be only for the specified ports.
func WithUDPDiscovery(ports ...string) Option {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("-PU%s", portList))
	}
}

// WithSCTPDiscovery sets the discovery mode to use SCTP packets
// containing a minimal INIT chunk.
// If the portList argument is empty, this will enable SCTP discovery
// for all ports. Otherwise, it will be only for the specified ports.
// Warning: on Unix, only the privileged user root is generally
// able to send and receive raw SCTP packets.
func WithSCTPDiscovery(ports ...string) Option {
	portList := strings.Join(ports, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("-PY%s", portList))
	}
}

// WithICMPEchoDiscovery sets the discovery mode to use an ICMP type 8
// packet (an echo request), like the standard packets sent by the ping
// command.
// Many hosts and firewalls block these packets, so this is usually not
// the best for exploring networks.
func WithICMPEchoDiscovery() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-PE")
	}
}

// WithICMPTimestampDiscovery sets the discovery mode to use an ICMP type 13
// packet (a timestamp request).
// This query can be valuable when administrators specifically block echo
// request packets while forgetting that other ICMP queries can be used
// for the same purpose.
func WithICMPTimestampDiscovery() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-PP")
	}
}

// WithICMPNetMaskDiscovery sets the discovery mode to use an ICMP type 17
// packet (an address mask request).
// This query can be valuable when administrators specifically block echo
// request packets while forgetting that other ICMP queries can be used
// for the same purpose.
func WithICMPNetMaskDiscovery() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-PM")
	}
}

// WithIPProtocolPingDiscovery sets the discovery mode to use the IP
// protocol ping.
// If no protocols are specified, the default is to send multiple IP
// packets for ICMP (protocol 1), IGMP (protocol 2), and IP-in-IP
// (protocol 4).
func WithIPProtocolPingDiscovery(protocols ...string) Option {
	protocolList := strings.Join(protocols, ",")

	return func(s *Scanner) {
		s.args = append(s.args, fmt.Sprintf("-PO%s", protocolList))
	}
}

// WithDisabledDNSResolution disables DNS resolution in the discovery
// step of the nmap scan.
func WithDisabledDNSResolution() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-n")
	}
}

// WithForcedDNSResolution enforces DNS resolution in the discovery
// step of the nmap scan.
func WithForcedDNSResolution() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-R")
	}
}

// WithCustomDNSServers sets custom DNS servers for the scan.
// List format: dns1[,dns2],...
func WithCustomDNSServers(dnsServers ...string) Option {
	dnsList := strings.Join(dnsServers, ",")

	return func(s *Scanner) {
		s.args = append(s.args, "--dns-servers")
		s.args = append(s.args, dnsList)
	}
}

// WithSystemDNS sets the scanner's DNS to the system's DNS.
func WithSystemDNS() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--system-dns")
	}
}

// WithTraceRoute enables the tracing of the hop path to each host.
func WithTraceRoute() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--traceroute")
	}
}
