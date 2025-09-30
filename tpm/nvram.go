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
	emptyPass   = ""
	certAttr    = tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear
	ownerHandle = tpm2.HandleOwner
)

var (
	ErrTooMuchData = errors.New("Too much data written to TPM NVRAM")
)

type nvoptions struct {
	ownerHandle tpmutil.Handle
	password    string
	blockSize   int
	attributes  tpm2.NVAttr
}

type NVOption func(*nvoptions) error

func WithOwnerHandle(handle tpmutil.Handle) NVOption {
	return func(o *nvoptions) error {
		o.ownerHandle = handle
		return nil
	}
}

func WithPassword(password string) NVOption {
	return func(o *nvoptions) error {
		if password != "" {
			o.password = password
		}
		return nil
	}
}

func WithBlockSize(size int) NVOption {
	return func(o *nvoptions) error {
		o.blockSize = size
		return nil
	}
}

func WithAttributes(attr tpm2.NVAttr) NVOption {
	return func(o *nvoptions) error {
		o.attributes = attr
		return nil
	}
}

func setNVOptions(opts ...NVOption) *nvoptions {
	options := nvoptions{
		ownerHandle: ownerHandle,
		password:    emptyPass,
		blockSize:   0,
		attributes:  certAttr,
	}
	for _, o := range opts {
		if err := o(&options); err != nil {
			return nil
		}
	}
	return &options
}

// NVRead reads data from the TPM NVRAM at the specified index.
func (t *TPM) NVRead(ctx context.Context, index uint32, opts ...NVOption) (data []byte, err error) {

	options := setNVOptions(opts...)
	return tpm2.NVReadEx(t.rwc, tpmutil.Handle(index), options.ownerHandle, options.password, options.blockSize)
}

// NVWrite writes data to the TPM NVRAM at the specified index.
func (t *TPM) NVWrite(ctx context.Context, index uint32, data []byte, opts ...NVOption) (err error) {

	offset := uint16(0)
	dataLen := uint16(len(data))
	if dataLen > 1024 {
		// not sure why there seems to be a 1024 byte limit (at least in sumulator)
		return ErrTooMuchData
	}
	options := setNVOptions(opts...)
	dataIndex := tpmutil.Handle(index)
	if err := tpm2.NVDefineSpace(t.rwc, options.ownerHandle, dataIndex, options.password, options.password, nil, options.attributes, dataLen); err != nil {
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
func (t *TPM) NVDelete(ctx context.Context, index uint32, opts ...NVOption) (err error) {

	options := setNVOptions(opts...)
	return tpm2.NVUndefineSpace(t.rwc, options.password, options.ownerHandle, tpmutil.Handle(index))
}

// LoadCertificateChain reads a chain of certificates from the TPM NVRAM at the specified index.
func (t *TPM) LoadCertificateChain(ctx context.Context, index uint32) (chain []*x509.Certificate, err error) {
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

// StoreCertificateChain writes a chain of certificates to the TPM NVRAM at the specified index.
func (t *TPM) StoreCertificateChain(ctx context.Context, index uint32, chain []*x509.Certificate) (err error) {
	buf := new(bytes.Buffer)
	for _, cert := range chain {
		if _, err := buf.Write(cert.Raw); err != nil {
			return fmt.Errorf("failed to encode certificate: %w", err)
		}
	}

	return t.NVWrite(ctx, index, buf.Bytes())
}
