package tpm

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/x509util"
)

func TestNVReadWriteCertificateChain(t *testing.T) {
	tpm := newOpenedTPM(t)
	t.Cleanup(func() { closeTPM(context.Background(), tpm, nil) })
	ctx := context.Background()

	// Generate a sample certificate chain
	rootCA, err := minica.New()
	require.NoError(t, err)

	intermediateSigner, err := keyutil.GenerateSigner("RSA", "", 2048)
	require.NoError(t, err)
	intermediateCR, err := x509util.NewCertificateRequest(intermediateSigner)
	require.NoError(t, err)
	intermediateCR.Subject.CommonName = "Intermediate CA"
	csr, err := intermediateCR.GetCertificateRequest()
	require.NoError(t, err)
	intermediateCert, err := rootCA.SignCSR(csr)
	require.NoError(t, err)

	leafSigner, err := keyutil.GenerateSigner("RSA", "", 2048)
	require.NoError(t, err)
	leafCR, err := x509util.NewCertificateRequest(leafSigner)
	require.NoError(t, err)
	leafCR.Subject.CommonName = "Leaf Certificate"
	intermediateCA, err := minica.New(
		minica.WithGetSignerFunc(func() (crypto.Signer, error) {
			return intermediateSigner, nil
		}),
		minica.WithRootTemplate(x509util.DefaultIntermediateTemplate),
	)
	require.NoError(t, err)
	intermediateCA.Root = intermediateCert

	leafCSR, err := leafCR.GetCertificateRequest()
	require.NoError(t, err)
	leafCert, err := intermediateCA.SignCSR(leafCSR)
	require.NoError(t, err)

	chain := []*x509.Certificate{leafCert}
	t.Logf("Certificate chain length: %d", len(chain))

	// Define a test NVRAM index
	const testNVRAMIndex uint32 = 0x1c00004 // A free index

	defer tpm.NVDelete(ctx, testNVRAMIndex)

	// Write the certificate chain
	err = tpm.WriteCertificateChain(ctx, testNVRAMIndex, chain)
	require.NoError(t, err)

	// Read the certificate chain
	readChain, err := tpm.ReadCertificateChain(ctx, testNVRAMIndex)
	require.NoError(t, err)

	// Validate the chain
	require.Len(t, readChain, len(chain))
	for i := range chain {
		require.True(t, chain[i].Equal(readChain[i]), "Certificate at index %d does not match", i)
	}

	// Clean up NVRAM
	err = tpm.NVDelete(ctx, testNVRAMIndex)
	require.NoError(t, err)
}
