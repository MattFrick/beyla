// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64
// +build arm64

package gogc

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpf_debugGcEvent struct {
	StartMonotimeNs uint64
	Action          uint32
	Lang            uint32
}

// loadBpf_debug returns the embedded CollectionSpec for bpf_debug.
func loadBpf_debug() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Bpf_debugBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf_debug: %w", err)
	}

	return spec, err
}

// loadBpf_debugObjects loads bpf_debug and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpf_debugObjects
//	*bpf_debugPrograms
//	*bpf_debugMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpf_debugObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf_debug()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpf_debugSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_debugSpecs struct {
	bpf_debugProgramSpecs
	bpf_debugMapSpecs
}

// bpf_debugSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_debugProgramSpecs struct {
	UprobeRuntimeFreeStackSpans        *ebpf.ProgramSpec `ebpf:"uprobe_runtime_freeStackSpans"`
	UprobeRuntimeGcBgMarkStartWorkers  *ebpf.ProgramSpec `ebpf:"uprobe_runtime_gcBgMarkStartWorkers"`
	UprobeRuntimeStartTheWorldWithSema *ebpf.ProgramSpec `ebpf:"uprobe_runtime_start_the_world_with_sema"`
	UprobeRuntimeStopTheWorldWithSema  *ebpf.ProgramSpec `ebpf:"uprobe_runtime_stop_the_world_with_sema"`
}

// bpf_debugMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpf_debugMapSpecs struct {
	Events         *ebpf.MapSpec `ebpf:"events"`
	OngoingGoGc    *ebpf.MapSpec `ebpf:"ongoing_go_gc"`
	OngoingGoStwGc *ebpf.MapSpec `ebpf:"ongoing_go_stw_gc"`
}

// bpf_debugObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpf_debugObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_debugObjects struct {
	bpf_debugPrograms
	bpf_debugMaps
}

func (o *bpf_debugObjects) Close() error {
	return _Bpf_debugClose(
		&o.bpf_debugPrograms,
		&o.bpf_debugMaps,
	)
}

// bpf_debugMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpf_debugObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_debugMaps struct {
	Events         *ebpf.Map `ebpf:"events"`
	OngoingGoGc    *ebpf.Map `ebpf:"ongoing_go_gc"`
	OngoingGoStwGc *ebpf.Map `ebpf:"ongoing_go_stw_gc"`
}

func (m *bpf_debugMaps) Close() error {
	return _Bpf_debugClose(
		m.Events,
		m.OngoingGoGc,
		m.OngoingGoStwGc,
	)
}

// bpf_debugPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpf_debugObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpf_debugPrograms struct {
	UprobeRuntimeFreeStackSpans        *ebpf.Program `ebpf:"uprobe_runtime_freeStackSpans"`
	UprobeRuntimeGcBgMarkStartWorkers  *ebpf.Program `ebpf:"uprobe_runtime_gcBgMarkStartWorkers"`
	UprobeRuntimeStartTheWorldWithSema *ebpf.Program `ebpf:"uprobe_runtime_start_the_world_with_sema"`
	UprobeRuntimeStopTheWorldWithSema  *ebpf.Program `ebpf:"uprobe_runtime_stop_the_world_with_sema"`
}

func (p *bpf_debugPrograms) Close() error {
	return _Bpf_debugClose(
		p.UprobeRuntimeFreeStackSpans,
		p.UprobeRuntimeGcBgMarkStartWorkers,
		p.UprobeRuntimeStartTheWorldWithSema,
		p.UprobeRuntimeStopTheWorldWithSema,
	)
}

func _Bpf_debugClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_debug_bpfel_arm64.o
var _Bpf_debugBytes []byte
