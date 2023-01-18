package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// NewEBPF returns a new loaded EBPF.
func NewEBPF() (*EBPF, error) {
	e := New()
	if err := e.Load(); err != nil {
		return nil, err
	}

	return e, nil
}

// NewEBPFWithLink returns a new loaded EBPF by loading the link.
func NewEBPFWithLink() (*EBPF, error) {
	e, err := NewEBPF()
	if err != nil {
		return nil, err
	}

	if err := e.loadAttachedLink(); err != nil {
		if closeErr := e.Close(); closeErr != nil {
			return nil, fmt.Errorf("%s: %w", err, closeErr)
		}
		return nil, err
	}

	return e, nil
}

// loadAttachedLink returns the pinned link from the FS.
func (e *EBPF) loadAttachedLink() error {
	l, err := link.LoadPinnedLink(e.linkPinFile(), &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("%s: %w", err, ErrNoAttach)
	}

	e.L = l
	return nil
}
