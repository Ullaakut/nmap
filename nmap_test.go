package nmap

import (
	"bytes"
	"log"
	"os"
	"reflect"
	"testing"

	nmaptesting "github.com/Ullaakut/nmap/v4/internal/testing"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	ctr, err := nmaptesting.StartNetworkMapper()
	if err != nil {
		log.Println("unable to start nmap test container, skipping container-based tests:", err)
		return
	}

	code := m.Run()

	err = nmaptesting.StopContainer(ctr)
	if err != nil {
		log.Println(err)
	}

	os.Exit(code)
}

func TestCheckStdErr(t *testing.T) {
	tests := []struct {
		description string
		stderr      string
		warnings    []string
		expectedErr error
	}{
		{
			description: "Find no error warning",
			stderr:      " NoWarning  \nNoWarning  ",
			warnings:    []string{"NoWarning", "NoWarning"},
			expectedErr: nil,
		},
		{
			description: "Find malloc error",
			stderr:      "   Malloc Failed! with ",
			warnings:    []string{"Malloc Failed! with"},
			expectedErr: ErrMallocFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			buf := bytes.Buffer{}
			_, _ = buf.Write([]byte(test.stderr))
			warnings, err := checkStdErr(&buf)

			assert.Equal(t, test.expectedErr, err)
			assert.True(t, reflect.DeepEqual(test.warnings, warnings))
		})
	}
}
