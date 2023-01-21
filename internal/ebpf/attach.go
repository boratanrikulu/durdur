package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
)

var FS = "/sys/fs/bpf"

var (
	ErrAlreadyAttached = fmt.Errorf("already attached to the interface")
	ErrNoAttach        = fmt.Errorf("not attached to the interface")
)

// Attach attaches eBPF program to the kernel.
func (e *EBPF) Attach(iface *net.Interface) error {
	if e.L != nil {
		return fmt.Errorf(
			"%w: %s", ErrAlreadyAttached, iface.Name,
		)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   e.Objects.XdpDurdurFunc,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attach: %w", err)
	}

	if err := l.Pin(e.linkPinFile()); err != nil {
		// TODO: fix multiple interface usage issue.
		return fmt.Errorf("pin link: %w", err)
	}

	e.L = l
	return nil
}

// linkPinFile returns FS file address for the link.
func (e *EBPF) linkPinFile() string {
	return fmt.Sprintf("%s/%s", FS, "xdp_durdur_link")
}
