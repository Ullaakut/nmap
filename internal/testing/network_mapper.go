package testing

import (
	"context"
	"fmt"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// ContainerName is the name given to the nmap test container.
const ContainerName = "nmap-test"

// StartNetworkMapper starts a container with nmap installed and returns it.
func StartNetworkMapper() (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Image: "instrumentisto/nmap:7.98",
		Name:  ContainerName,
		Cmd:   []string{"sleep", "infinity"},
		WaitingFor: wait.ForExec([]string{"nmap", "--version"}).
			WithStartupTimeout(time.Minute),
	}
	ctr, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("starting nmap container: %w", err)
	}

	return ctr, nil
}

// StopContainer terminates a testcontainer.
func StopContainer(ctr testcontainers.Container) error {
	if ctr == nil {
		return nil
	}
	return ctr.Terminate(context.Background())
}
