package ebpf

import (
	"fmt"
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

	if err := e.Objects.BpfMaps.DropFromAddrs.Unpin(); err != nil {
		return fmt.Errorf("detach %s map: %w",
			e.Objects.BpfMaps.DropFromAddrs.String(), err)
	}

	if err := e.Objects.BpfMaps.DropFromAddrs.Close(); err != nil {
		return fmt.Errorf("detach %s map: %w",
			e.Objects.BpfMaps.DropFromAddrs.String(), err)
	}

	if err := e.Objects.BpfMaps.DropToAddrs.Unpin(); err != nil {
		return fmt.Errorf("close %s map: %w",
			e.Objects.BpfMaps.DropToAddrs.String(), err)
	}

	if err := e.Objects.BpfMaps.DropToAddrs.Close(); err != nil {
		return fmt.Errorf("close %s map: %w",
			e.Objects.BpfMaps.DropToAddrs.String(), err)
	}

	return nil
}
