package ebpf

import (
	"fmt"

	"github.com/boratanrikulu/durdur/internal/generated"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// EBPF keeps eBPF Objects(BpfPrograms, BpfMaps) and Link.
type EBPF struct {
	Objects *generated.BpfObjects
	L       link.Link
}

// New returns a new EBPF.
func New() *EBPF {
	return &EBPF{
		Objects: &generated.BpfObjects{},
	}
}

// Load loads pre-compiled eBPF program.
func (e *EBPF) Load() error {
	spec, err := generated.LoadBpf()
	if err != nil {
		return fmt.Errorf("load ebpf: %w", err)
	}

	spec.Maps["drop_src_addrs"].Pinning = ebpf.PinByName
	spec.Maps["drop_dns"].Pinning = ebpf.PinByName
	if err := spec.LoadAndAssign(e.Objects, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: FS,
		},
	}); err != nil {
		return fmt.Errorf("load and assign: %w", err)
	}

	return nil
}

// Close cleans all resources.
func (e *EBPF) Close() error {
	if e.Objects != nil {
		if err := e.Objects.Close(); err != nil {
			return err
		}
	}

	if e.L != nil {
		if err := e.L.Close(); err != nil {
			return err
		}
	}

	return nil
}
