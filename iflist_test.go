package nmap

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestScanner_GetInterfaceList(t *testing.T) {
	scanner, err := NewScanner(WithBinaryPath("tests/scripts/fake_nmap_iflist.sh"))
	assert.NoError(t, err)

	result, err := scanner.GetInterfaceList()

	assert.NoError(t, err)
	assert.NotNil(t, result)

	assert.Len(t, result.Interfaces, 2)
	assert.Len(t, result.Routes, 2)
}

func TestConvertInterface(t *testing.T) {
	i := convertInterface("lo     (lo)     127.0.0.1/8                               loopback down 65536 11:11:11:11:11:11")

	assert.Equal(t, "lo", i.Device)
	assert.Equal(t, "(lo)", i.Short)
	assert.Equal(t, net.ParseIP("127.0.0.1"), i.IP)
	assert.Equal(t, net.ParseIP("255.0.0.0").To4(), i.IPMask)
	assert.Equal(t, "loopback", i.Type)
	assert.False(t, i.Up)
	assert.Equal(t, 65536, i.MTU)
	assert.Equal(t, net.HardwareAddr{0x11, 0x11, 0x11, 0x11, 0x11, 0x11}, i.Mac)
}

func TestConvertRoute(t *testing.T) {
	r := convertRoute("192.168.0.0/24                            wlp5s0 600 192.168.0.1")

	assert.Equal(t, net.ParseIP("192.168.0.0"), r.DestinationIP)
	assert.Equal(t, net.ParseIP("255.255.255.0").To4(), r.DestinationIPMask)
	assert.Equal(t, "wlp5s0", r.Device)
	assert.Equal(t, 600, r.Metric)
	assert.Equal(t, net.ParseIP("192.168.0.1"), r.Gateway)
}
