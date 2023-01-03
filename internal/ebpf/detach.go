package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Detach detaches all pinned objects from the FS.
func Detach() error {
	e, err := newEBPFWithLink()
	if err != nil {
		return err
	}
	defer e.Close()

	return e.Detach()
}

// Detach unpins and closes FS and maps.
func (e *EBPF) Detach() error {
	if err := e.L.Unpin(); err != nil {
		return fmt.Errorf("detach the link: %w", err)
	}

	if err := e.L.Close(); err != nil {
		return fmt.Errorf("close the link: %w", err)
	}

	for _, m := range []*ebpf.Map{
		e.Objects.BpfMaps.DropFromAddrs,
		e.Objects.BpfMaps.DropToAddrs,
		e.Objects.BpfMaps.DropDns,
	} {
		if err := m.Unpin(); err != nil {
			return fmt.Errorf("detach %s map: %w", m.String(), err)
		}

		if err := m.Close(); err != nil {
			return fmt.Errorf("clear %s map: %w", m.String(), err)
		}
	}

	return nil
}
