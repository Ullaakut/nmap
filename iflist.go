package nmap

import (
	"bytes"
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

// Interface is a interface object.
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

// GetInterfaceList runs nmap with the --iflist option. The output will be parsed.
// The return value is a struct containing all host interfaces and routes.
func (s *Scanner) GetInterfaceList() (result *InterfaceList, err error) {
	var stdout, stderr bytes.Buffer

	args := append(s.args, "--iflist")

	// Prepare nmap process
	cmd := exec.Command(s.binaryPath, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run nmap process
	err = cmd.Run()
	if err != nil {
		return nil, err
	}

	result = parseInterfaces(stdout.Bytes())

	return result, nil
}

func parseInterfaces(content []byte) *InterfaceList {
	list := InterfaceList{
		Interfaces: make([]*Interface, 0),
		Routes:     make([]*Route, 0),
	}
	output := string(content)
	lines := strings.Split(output, "\n")

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
	if ip, val, err := net.ParseCIDR(fields[2]); err == nil {
		iface.IP = ip
		iface.IPMask = net.IP(val.Mask)
	}

	iface.Up = strings.ToLower(fields[4]) == "up"

	if val, err := strconv.Atoi(fields[5]); err == nil {
		iface.MTU = val
	}
	if len(fields) > 6 {
		if val, err := net.ParseMAC(fields[6]); err == nil {
			iface.Mac = val
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
	if ip, val, err := net.ParseCIDR(fields[0]); err == nil {
		route.DestinationIP = ip
		route.DestinationIPMask = net.IP(val.Mask)
	}
	if val, err := strconv.Atoi(fields[2]); err == nil {
		route.Metric = val
	}
	if len(fields) > 3 {
		route.Gateway = net.ParseIP(fields[3])
	}
	return route
}
