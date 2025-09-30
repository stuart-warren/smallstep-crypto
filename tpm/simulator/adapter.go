package simulator

import (
	"io"

	externalSimulator "github.com/google/go-tpm-tools/simulator"
)

// tpmToolsSimulatorAdapter adapts the external simulator to the local Simulator interface.
type tpmToolsSimulatorAdapter struct {
	io.ReadWriteCloser
}

// Open implements the Simulator interface.
func (a *tpmToolsSimulatorAdapter) Open() error {
	// The external simulator is opened when Get() is called.
	return nil
}

// MeasurementLog implements the Simulator interface with a dummy implementation.
func (a *tpmToolsSimulatorAdapter) MeasurementLog() ([]byte, error) {
	// This is a dummy implementation for testing purposes.
	return []byte("dummy measurement log"), nil
}

// GetAdapter returns a Simulator that wraps the external simulator.
func GetAdapter() (Simulator, error) {
	sim, err := externalSimulator.Get()
	if err != nil {
		return nil, err
	}
	return &tpmToolsSimulatorAdapter{sim},
			nil
}
