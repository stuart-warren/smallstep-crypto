package tpm

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"

	"errors"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	emptyPass          = ""
	CertIndex   uint32 = 0x01500001
	certAttr           = tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear
	ownerHandle        = tpm2.HandleOwner
)

var (
	ErrTooMuchData = errors.New("Too much data written to TPM NVRAM")
)

// NVRead reads data from the TPM NVRAM at the specified index.
func (t *TPM) NVRead(ctx context.Context, index uint32) (data []byte, err error) {

	offset := 0
	return tpm2.NVReadEx(t.rwc, tpmutil.Handle(index), tpm2.HandleOwner, emptyPass, offset)
}

// NVWrite writes data to the TPM NVRAM at the specified index.
func (t *TPM) NVWrite(ctx context.Context, index uint32, data []byte) (err error) {

	offset := uint16(0)
	dataLen := uint16(len(data))
	if dataLen > 1024 {
		// not sure why there seems to be a 1024 byte limit (at least in sumulator)
		return ErrTooMuchData
	}
	dataIndex := tpmutil.Handle(index)
	if err := tpm2.NVDefineSpace(t.rwc, ownerHandle, dataIndex, emptyPass, emptyPass, nil, certAttr, dataLen); err != nil {
		return fmt.Errorf("Failed to DefineSpace: %w", err)
	}
	if err := tpm2.NVWrite(t.rwc, ownerHandle, dataIndex, emptyPass, data, offset); err != nil {
		return fmt.Errorf("Failed to Write: %w", err)
	}
	readData, err := t.NVRead(ctx, index)
	if err != nil {
		return fmt.Errorf("Failed to Read written data: %w", err)
	}
	if !bytes.Equal(readData, data) {
		return fmt.Errorf("Failed to Read the same data as written")
	}
	return nil
}

// NVDelete deletes an index from the TPM NVRAM.
func (t *TPM) NVDelete(ctx context.Context, index uint32) (err error) {

	return tpm2.NVUndefineSpace(t.rwc, emptyPass, ownerHandle, tpmutil.Handle(index))
}

// ReadCertificateChain reads a chain of certificates from the TPM NVRAM at the specified index.
func (t *TPM) ReadCertificateChain(ctx context.Context, index uint32) (chain []*x509.Certificate, err error) {
	data, err := t.NVRead(ctx, index)
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

// WriteCertificateChain writes a chain of certificates to the TPM NVRAM at the specified index.
func (t *TPM) WriteCertificateChain(ctx context.Context, index uint32, chain []*x509.Certificate) (err error) {
	buf := new(bytes.Buffer)
	for _, cert := range chain {
		if _, err := buf.Write(cert.Raw); err != nil {
			return fmt.Errorf("failed to encode certificate: %w", err)
		}
	}

	return t.NVWrite(ctx, index, buf.Bytes())
}
