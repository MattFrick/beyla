// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64
// +build arm64

package javagc

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfJavaGc struct{ GcBeginMonotimeNs uint64 }

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	UprobeMemPoolGcBegin *ebpf.ProgramSpec `ebpf:"uprobe_MemPoolGcBegin"`
	UprobeMemPoolGcEnd   *ebpf.ProgramSpec `ebpf:"uprobe_MemPoolGcEnd"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	Events        *ebpf.MapSpec `ebpf:"events"`
	OngoingJavaGC *ebpf.MapSpec `ebpf:"ongoing_java_GC"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	Events        *ebpf.Map `ebpf:"events"`
	OngoingJavaGC *ebpf.Map `ebpf:"ongoing_java_GC"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.Events,
		m.OngoingJavaGC,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	UprobeMemPoolGcBegin *ebpf.Program `ebpf:"uprobe_MemPoolGcBegin"`
	UprobeMemPoolGcEnd   *ebpf.Program `ebpf:"uprobe_MemPoolGcEnd"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.UprobeMemPoolGcBegin,
		p.UprobeMemPoolGcEnd,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfel_arm64.o
var _BpfBytes []byte
