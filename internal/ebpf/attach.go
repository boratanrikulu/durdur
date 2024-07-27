package ebpf

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
)

var FS = "/sys/fs/bpf"

var (
	ErrAlreadyAttached = fmt.Errorf("already attached to the interface")
	ErrNoAttach        = fmt.Errorf("not attached to the interface")
)

// Attach attaches the eBPF program to the kernel with retry logic.
func (e *EBPF) Attach(iface *net.Interface) error {
	const maxRetries = 3
	const retryDelay = 100 * time.Millisecond

	if e.L != nil {
		return fmt.Errorf(
			"%w: %s", ErrAlreadyAttached, iface.Name,
		)
	}

	var l link.Link
	var err error
	for i := 0; i < maxRetries; i++ {
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   e.Objects.XdpDurdurFunc,
			Interface: iface.Index,
		})
		if err == nil {
			break
		}
		if i < maxRetries-1 {
			time.Sleep(retryDelay)
		}
	}
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
