package nmap

import (
	"bytes"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type InterfaceList struct {
	Interfaces []*Interface `json:"interfaces"`
	Routes     []*Route `json:"routes"`
}

type Interface struct {
	Device string `json:"device"`
	Short  string `json:"short"`
	IP     net.IP `json:"ip"`
	IPMask  net.IP `json:"ip_mask"`
	Type   string `json:"type"`
	Up     bool `json:"up"`
	MTU    int `json:"mtu"`
	Mac    net.HardwareAddr `json:"mac"`
}

type Route struct {
	DestinationIP net.IP `json:"destination_ip"`
	DestinationIPMask net.IP `json:"destination_ip_mask"`
	Device      string `json:"device"`
	Metric      int `json:"metric"`
	Gateway     net.IP `json:"gateway"`
}

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

func parseInterfaces(content []byte) (*InterfaceList) {
	list := InterfaceList{
		Interfaces: make([]*Interface, 0),
		Routes:     make([]*Route, 0),
	}
	output := string(content)
	lines := strings.Split(output, "\n")

	for i, line := range lines {
		if match, _ := regexp.MatchString(`[\*]INTERFACES[\*]`, line); match {
			for _, line := range lines[i+2:] {
				if iface := convertInterface(line); iface != nil {
					list.Interfaces = append(list.Interfaces, iface)
				}
			}
		}

		if match, _ := regexp.MatchString(`[\*]ROUTES[\*]`, line); match {
			for _, line := range lines[i+2:] {
				if route := convertRoute(line); route != nil {
					list.Routes = append(list.Routes, route)
				}
			}
		}
	}

	return &list
}

func convertInterface(line string) *Interface {
	splitted := strings.Fields(line)

	if len(splitted) < 6{
		return nil
	}
	iface := &Interface{
		Device: splitted[0],
		Short:  splitted[1],
		Type:   splitted[3],
	}
	if ip, val, err := net.ParseCIDR(splitted[2]); err == nil {
		iface.IP = ip
		iface.IPMask = net.IP(val.Mask)
	}
	if strings.ToLower(splitted[4]) == "up" {
		iface.Up = true
	} else {
		iface.Up = false
	}
	if val, err := strconv.Atoi(splitted[5]); err == nil {
		iface.MTU = val
	}
	if len(splitted) > 6 {
		if val, err := net.ParseMAC(splitted[6]); err == nil {
			iface.Mac = val
		}
	}
	return iface
}

func convertRoute(line string) *Route {
	splitted := strings.Fields(line)

	if len(splitted) < 3{
		return nil
	}

	route := &Route{
		Device: splitted[1],
	}
	if ip, val, err := net.ParseCIDR(splitted[0]); err == nil {
		route.DestinationIP = ip
		route.DestinationIPMask = net.IP(val.Mask)
	}
	if val, err := strconv.Atoi(splitted[2]); err == nil {
		route.Metric = val
	}
	if len(splitted) > 3 {
		route.Gateway = net.ParseIP(splitted[3])
	}
	return route
}
