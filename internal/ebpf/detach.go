package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Detach unpins and closes FS and maps.
func (e *EBPF) Detach() error {
	if e.L == nil {
		return ErrNoAttach
	}

	if err := e.Close(); err != nil {
		return fmt.Errorf("close the program: %w", err)
	}

	if err := e.L.Unpin(); err != nil {
		return fmt.Errorf("detach the link: %w", err)
	}

	for _, m := range []*ebpf.Map{
		e.Objects.BpfMaps.DropFromAddrs,
		e.Objects.BpfMaps.DropToAddrs,
		e.Objects.BpfMaps.DropDns,
	} {
		if err := m.Unpin(); err != nil {
			return fmt.Errorf("detach %s map: %w", m.String(), err)
		}
	}

	return nil
}
