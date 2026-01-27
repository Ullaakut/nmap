package nmap

import (
	"os/exec"
	"strings"
	"testing"

	nmaptesting "github.com/Ullaakut/nmap/v4/internal/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nmapContainerOptions(t *testing.T) []Option {
	t.Helper()

	ctx := t.Context()
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker is required to run container-based tests")
	}

	inspectCmd := exec.CommandContext(ctx, dockerPath, "inspect", "-f", "{{.State.Running}}", nmaptesting.ContainerName)
	if output, inspectErr := inspectCmd.Output(); inspectErr == nil {
		if strings.TrimSpace(string(output)) == "true" {
			return []Option{
				WithBinaryPath(dockerPath),
				WithCustomArguments("exec", nmaptesting.ContainerName, "nmap"),
			}
		}
	}

	ctr, err := nmaptesting.StartNetworkMapper()
	if err != nil {
		t.Skipf("unable to start nmap test container: %v", err)
	}
	if ctr != nil {
		t.Cleanup(func() {
			_ = nmaptesting.StopContainer(ctr)
		})
	}

	return []Option{
		WithBinaryPath(dockerPath),
		WithCustomArguments("exec", nmaptesting.ContainerName, "nmap"),
	}
}

func assertArgsSuffix(t *testing.T, args, expected []string) {
	t.Helper()

	require.Len(t, args, len(expected)+3) // accounting for "exec", "<container>", "nmap"
	args = args[3:]                       // strip "exec", "<container>", "nmap"

	require.Equal(t, len(args), len(expected))
	assert.Equal(t, args, expected)
}
