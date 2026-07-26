package nmap

import (
	"context"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewCmdWithCustomSysProcAttrInitializesAndPassesCommandAttribute(t *testing.T) {
	var callbackAttr *syscall.SysProcAttr

	scanner, err := NewScanner(
		WithBinaryPath("nmap"),
		WithCustomSysProcAttr(func(attr *syscall.SysProcAttr) {
			callbackAttr = attr
		}),
	)
	require.NoError(t, err)

	cmd := scanner.newCmd(context.Background())

	require.NotNil(t, cmd.SysProcAttr)
	require.NotNil(t, callbackAttr)
	require.Same(t, cmd.SysProcAttr, callbackAttr)
}
