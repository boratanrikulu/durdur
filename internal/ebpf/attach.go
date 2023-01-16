package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var FS = "/sys/fs/bpf"

var (
	ErrAlreadyAttached = fmt.Errorf("durdur is already attached to the interface")
	ErrNoAttach        = fmt.Errorf("durdur is not attached to the interface")
)

// Attach loads the eBPF program and attaches it to the kernel.
func Attach(iface *net.Interface) error {
	e, err := newEBPF()
	if err != nil {
		return err
	}
	defer e.Close()

	return e.Attach(iface)
}

// Attach attaches eBPF program to the kernel.
func (e *EBPF) Attach(iface *net.Interface) error {
	if err := e.LoadAttachedLink(); err == nil {
		return fmt.Errorf(
			"%w: %s", ErrAlreadyAttached, iface.Name,
		)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   e.Objects.XdpDurdurFunc,
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}

	if err := l.Pin(e.linkPinFile()); err != nil {
		return err
	}

	e.L = l
	return nil
}

// LoadAttachedLink returns the pinned link from the FS.
func (e *EBPF) LoadAttachedLink() error {
	l, err := link.LoadPinnedLink(e.linkPinFile(), &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("%s: %w", err, ErrNoAttach)
	}

	e.L = l
	return nil
}

// linkPinFile returns FS file address for the link.
func (e *EBPF) linkPinFile() string {
	return fmt.Sprintf("%s/%s", FS, "xdp_durdur_link")
}
