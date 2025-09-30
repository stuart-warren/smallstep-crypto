package tpmkms

import (
	"context"
	"crypto/x509"
	"testing"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/x509util"
)

func TestNVRAM(t *testing.T) {
	// This is a placeholder for actual NVRAM tests.
	// Implement tests for NVRAM read/write operations here.
	ctx := context.Background()
	index := "0x1500016"
	k, err := New(ctx, apiv1.Options{
		URI: "tpmkms:device=/home/stuartwarren/src/github.com/stuart-warren/smallstep-crypto/hack/swtpm-sock",
	})
	if err != nil {
		t.Fatalf("failed to create TPMKMS: %v", err)
	}
	k.WithNVOptions(tpm.WithPassword("")) // Add actual NV options as needed.
	ak, err := k.tpm.CreateAK(ctx, index)
	if err != nil {
		t.Fatalf("failed to create AK: %v", err)
	}
	rootCa, err := minica.New()
	if err != nil {
		t.Fatalf("failed to create minica: %v", err)
	}
	aksigner, err := k.tpm.GetSigner(ctx, index)
	if err != nil {
		t.Fatalf("failed to get AK signer: %v", err)
	}
	leafCR, err := x509util.NewCertificateRequest(aksigner)
	if err != nil {
		t.Fatalf("failed to create certificate request: %v", err)
	}
	leafCR.Subject.CommonName = "Leaf Certificate"
	leafCSR, err := leafCR.GetCertificateRequest()
	if err != nil {
		t.Fatalf("failed to get certificate request: %v", err)
	}
	leafCert, err := rootCa.SignCSR(leafCSR)
	if err != nil {
		t.Fatalf("failed to sign CSR: %v", err)
	}
	err = ak.SetCertificateChain(ctx, []*x509.Certificate{leafCert, rootCa.Root})
	if err != nil {
		t.Fatalf("failed to set certificate chain: %v", err)
	}
	err = k.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name:        index,
		Certificate: leafCert,
	})
}
