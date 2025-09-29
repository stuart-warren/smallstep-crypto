package main

import (
	"bytes"
	"log"

	"github.com/google/go-tpm-tools/simulator" // Import the simulator package
	ltpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func main() {
	// 1. Open the TPM simulator
	tpm, err := simulator.Get()
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer tpm.Close() // Ensure the simulator is closed when the function exits

	// Use a specific NV index for this example
	nvIndex := tpmutil.Handle(0x01500001) // Example index, must be unused

	// Data to write to NVRAM
	writeData := []byte("secret_data_for_nvram_storage")
	dataSize := uint16(len(writeData))

	attr := ltpm2.AttrOwnerWrite | ltpm2.AttrOwnerRead | ltpm2.AttrWriteSTClear | ltpm2.AttrReadSTClear
	emptyAuth := ""

	// if err := ltpm2.NVUndefineSpace(tpm, emptyAuth, ltpm2.HandleOwner, nvIndex); err != nil {
	// 	log.Fatalf("failed to undefine NV space: %v", err)
	// }

	if err := ltpm2.NVDefineSpace(tpm, ltpm2.HandleOwner, nvIndex, emptyAuth, emptyAuth, nil, attr, dataSize); err != nil {
		log.Fatalf("failed to define NV space: %v", err)
	}

	defer ltpm2.NVUndefineSpace(tpm, emptyAuth, ltpm2.HandleOwner, nvIndex) // Clean up NV space on exit

	if err := ltpm2.NVWrite(tpm, ltpm2.HandleOwner, nvIndex, emptyAuth, writeData, 0); err != nil {
		log.Fatalf("failed to write to NV space: %v", err)
	}

	if err := ltpm2.NVWriteLock(tpm, ltpm2.HandleOwner, nvIndex, emptyAuth); err != nil {
		log.Fatalf("failed to lock NV space: %v", err)
	}

	pub, err := ltpm2.NVReadPublic(tpm, nvIndex)
	if err != nil {
		log.Fatalf("failed to read NV public area: %v", err)
	}

	if pub.DataSize != dataSize {
		log.Fatalf("unexpected NV size: got %d, want %d", pub.DataSize, dataSize)
	}

	outData, err := ltpm2.NVReadEx(tpm, nvIndex, ltpm2.HandleOwner, emptyAuth, 0)
	if err != nil {
		log.Fatalf("failed to read from NV space: %v", err)
	}

	if !bytes.Equal(outData, writeData) {
		log.Fatalf("data mismatch: got %v, want %v", outData, writeData)
	}

}
