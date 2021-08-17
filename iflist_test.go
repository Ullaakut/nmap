package nmap

import (
	"testing"
)

func TestScanner_GetInterfaceList(t *testing.T) {
	scanner, err := NewScanner(WithBinaryPath("tests/scripts/fake_nmap_iflist.sh"))
	if err != nil {
		t.Error(err)
	}

	result, err := scanner.GetInterfaceList()
	if err != nil {
		t.Error(err)
	}

	if len(result.Interfaces) != 2 {
		t.Error("There should be 2 interfaces inside")
	}

	if len(result.Routes) != 2 {
		t.Error("There should be 2 routes inside")
	}
}

func TestConvertInterface(t *testing.T) {
	i := convertInterface("lo     (lo)     127.0.0.1/8                               loopback down 65536")

	if i.Up {
		t.Error("Interface should be down")
	}
}
