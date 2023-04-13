package nmap

import (
	"fmt"
	"strings"
)

// WithFragmentPackets enables the use of tiny fragmented IP packets in order to
// split up the TCP header over several packets to make it harder for packet
// filters, intrusion detection systems, and other annoyances to detect what
// you are doing.
// Some programs have trouble handling these tiny packets.
func WithFragmentPackets() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-f")
	}
}

// WithMTU allows you to specify your own offset size for fragmenting IP packets.
// Using fragmented packets allows to split up the TCP header over several packets
// to make it harder for packet filters, intrusion detection systems, and other
// annoyances to detect what you are doing.
// Some programs have trouble handling these tiny packets.
func WithMTU(offset int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--mtu")
		s.args = append(s.args, fmt.Sprint(offset))
	}
}

// WithDecoys causes a decoy scan to be performed, which makes it appear to the
// remote host that the host(s) you specify as decoys are scanning the target
// network too. Thus their IDS might report 5–10 port scans from unique IP
// addresses, but they won't know which IP was scanning them and which were
// innocent decoys.
// While this can be defeated through router path tracing, response-dropping,
// and other active mechanisms, it is generally an effective technique for
// hiding your IP address.
// You can optionally use ME as one of the decoys to represent the position
// for your real IP address.
// If you put ME in the sixth position or later, some common port scan
// detectors are unlikely to show your IP address at all.
func WithDecoys(decoys ...string) Option {
	decoyList := strings.Join(decoys, ",")

	return func(s *Scanner) {
		s.args = append(s.args, "-D")
		s.args = append(s.args, decoyList)
	}
}

// WithSpoofIPAddress spoofs the IP address of the machine which is running nmap.
// This can be used if nmap is unable to determine your source address.
// Another possible use of this flag is to spoof the scan to make the targets
// think that someone else is scanning them. The WithInterface option and
// WithSkipHostDiscovery are generally required for this sort of usage. Note
// that you usually won't receive reply packets back (they will be addressed to
// the IP you are spoofing), so Nmap won't produce useful reports.
func WithSpoofIPAddress(ip string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-S")
		s.args = append(s.args, ip)
	}
}

// WithInterface specifies which network interface to use for scanning.
func WithInterface(iface string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-e")
		s.args = append(s.args, iface)
	}
}

// WithSourcePort specifies from which port to scan.
func WithSourcePort(port uint16) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--source-port")
		s.args = append(s.args, fmt.Sprint(port))
	}
}

// WithProxies allows to relay connection through HTTP/SOCKS4 proxies.
func WithProxies(proxies ...string) Option {
	proxyList := strings.Join(proxies, ",")

	return func(s *Scanner) {
		s.args = append(s.args, "--proxies")
		s.args = append(s.args, proxyList)
	}
}

// WithHexData appends a custom hex-encoded payload to sent packets.
func WithHexData(data string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--data")
		s.args = append(s.args, data)
	}
}

// WithASCIIData appends a custom ascii-encoded payload to sent packets.
func WithASCIIData(data string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--data-string")
		s.args = append(s.args, data)
	}
}

// WithDataLength appends a random payload of the given length to sent packets.
func WithDataLength(length int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--data-length")
		s.args = append(s.args, fmt.Sprint(length))
	}
}

// WithIPOptions uses the specified IP options to send packets.
// You may be able to use the record route option to determine a
// path to a target even when more traditional traceroute-style
// approaches fail. See http://seclists.org/nmap-dev/2006/q3/52
// for examples of use.
func WithIPOptions(options string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--ip-options")
		s.args = append(s.args, options)
	}
}

// WithIPTimeToLive sets the IP time-to-live field of IP packets.
func WithIPTimeToLive(ttl int16) Option {
	return func(s *Scanner) {
		if ttl < 0 || ttl > 255 {
			panic("value given to nmap.WithIPTimeToLive() should be between 0 and 255")
		}

		s.args = append(s.args, "--ttl")
		s.args = append(s.args, fmt.Sprint(ttl))
	}
}

// WithSpoofMAC uses the given MAC address for all of the raw
// ethernet frames the scanner sends. This option implies
// WithSendEthernet to ensure that Nmap actually sends ethernet-level
// packets.
// Valid argument examples are Apple, 0, 01:02:03:04:05:06,
// deadbeefcafe, 0020F2, and Cisco.
func WithSpoofMAC(argument string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--spoof-mac")
		s.args = append(s.args, argument)
	}
}

// WithBadSum makes nmap send an invalid TCP, UDP or SCTP checksum
// for packets sent to target hosts. Since virtually all host IP
// stacks properly drop these packets, any responses received are
// likely coming from a firewall or IDS that didn't bother to
// verify the checksum.
func WithBadSum() Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--badsum")
	}
}
