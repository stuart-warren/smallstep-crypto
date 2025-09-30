package tpm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	localSimulator "go.step.sm/crypto/tpm/simulator"

	"go.step.sm/crypto/tpm/storage"
)

func newOpenedTPM(t *testing.T) *TPM {
	t.Helper()
	sim, err := localSimulator.GetAdapter()
	require.NoError(t, err)

	tpm, err := New(WithSimulator(sim))
	require.NoError(t, err)
	err = tpm.open(context.Background())
	require.NoError(t, err)
	return tpm
}



func TestTPMNoStorageConfiguredError(t *testing.T) {
	err := ErrNoStorageConfigured
	require.ErrorIs(t, err, storage.ErrNoStorageConfigured)
}