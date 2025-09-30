package tpmkms

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/tpm"
)

func nameToUint32(name string) (uint32, error) {
	var val uint32
	n, err := fmt.Sscanf(name, "0x%X", &val)
	if n != 1 || err != nil {
		return 0, fmt.Errorf("invalid NVRAM index name %q", name)
	}
	return val, nil
}

func (k *TPMKMS) WithNVOptions(opts ...tpm.NVOption) {
	k.nvoptions = opts
}

func (k *TPMKMS) usesNVRAM() bool {
	return k.nvoptions != nil
}

func (k *TPMKMS) storeCertificateChainToNVRAM(req *apiv1.StoreCertificateChainRequest) error {
	ctx := context.Background()
	index, err := nameToUint32(req.Name)
	if err != nil {
		return fmt.Errorf("invalid NVRAM index name %q: %w", req.Name, err)
	}

	buf := new(bytes.Buffer)
	for _, cert := range req.CertificateChain {
		if _, err := buf.Write(cert.Raw); err != nil {
			return fmt.Errorf("failed to encode certificate: %w", err)
		}
	}

	return k.tpm.NVWrite(ctx, index, buf.Bytes(), k.nvoptions...)
}

func (k *TPMKMS) loadCertificateChainFromNVRAM(req *apiv1.LoadCertificateChainRequest) ([]*x509.Certificate, error) {
	ctx := context.Background()
	index, err := nameToUint32(req.Name)
	if err != nil {
		return nil, fmt.Errorf("invalid NVRAM index name %q: %w", req.Name, err)
	}
	data, err := k.tpm.NVRead(ctx, index, k.nvoptions...)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	certs, err = x509.ParseCertificates(data)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("failed to parse certificates: %w", err)
	}

	return certs, nil
}
