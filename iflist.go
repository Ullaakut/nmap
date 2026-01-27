package nmap

import (
	"bytes"
	"context"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// InterfaceList contains interfaces and routes.
type InterfaceList struct {
	Interfaces []*Interface `json:"interfaces"`
	Routes     []*Route     `json:"routes"`
}

// Interface is an interface object.
type Interface struct {
	Device string           `json:"device"`
	Short  string           `json:"short"`
	IP     net.IP           `json:"ip"`
	IPMask net.IP           `json:"ip_mask"`
	Type   string           `json:"type"`
	Up     bool             `json:"up"`
	MTU    int              `json:"mtu"`
	Mac    net.HardwareAddr `json:"mac"`
}

// Route is a route object.
type Route struct {
	DestinationIP     net.IP `json:"destination_ip"`
	DestinationIPMask net.IP `json:"destination_ip_mask"`
	Device            string `json:"device"`
	Metric            int    `json:"metric"`
	Gateway           net.IP `json:"gateway"`
}

// InterfaceList runs nmap with the --iflist option.
// The return value is a struct containing all host interfaces and routes.
func (s *Scanner) InterfaceList(ctx context.Context) (*InterfaceList, error) {
	args := append([]string{}, s.args...)
	args = append(args, "--iflist")

	// Prepare nmap process
	//nolint:gosec // Arguments are passed directly to nmap; users intentionally control args.
	cmd := exec.CommandContext(ctx, s.binaryPath, args...)

	// Bind stdout and stderr.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run nmap process.
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	return parseInterfaces(stdout.String()), nil
}

func parseInterfaces(content string) *InterfaceList {
	list := InterfaceList{
		Interfaces: make([]*Interface, 0),
		Routes:     make([]*Route, 0),
	}
	lines := strings.Split(content, "\n")

	interfaceRegex := regexp.MustCompile(`\*INTERFACES\*`)
	routesRegex := regexp.MustCompile(`\*ROUTES\*`)
	for i, line := range lines {
		if interfaceRegex.MatchString(line) {
			for _, l := range lines[i+2:] {
				if iface := convertInterface(l); iface != nil {
					list.Interfaces = append(list.Interfaces, iface)
				}
			}
		}

		if routesRegex.MatchString(line) {
			for _, l := range lines[i+2:] {
				if route := convertRoute(l); route != nil {
					list.Routes = append(list.Routes, route)
				}
			}
		}
	}

	return &list
}

func convertInterface(line string) *Interface {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return nil
	}

	iface := &Interface{
		Device: fields[0],
		Short:  fields[1],
		Type:   fields[3],
	}

	ip, ipnet, err := net.ParseCIDR(fields[2])
	if err == nil {
		iface.IP = ip
		iface.IPMask = net.IP(ipnet.Mask)
	}

	iface.Up = strings.ToLower(fields[4]) == "up"

	mtu, err := strconv.Atoi(fields[5])
	if err == nil {
		iface.MTU = mtu
	}

	if len(fields) > 6 {
		mac, err := net.ParseMAC(fields[6])
		if err == nil {
			iface.Mac = mac
		}
	}
	return iface
}

func convertRoute(line string) *Route {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil
	}

	route := &Route{
		Device: fields[1],
	}

	ip, ipnet, err := net.ParseCIDR(fields[0])
	if err == nil {
		route.DestinationIP = ip
		route.DestinationIPMask = net.IP(ipnet.Mask)
	}

	metric, err := strconv.Atoi(fields[2])
	if err == nil {
		route.Metric = metric
	}

	if len(fields) > 3 {
		route.Gateway = net.ParseIP(fields[3])
	}

	return route
}
