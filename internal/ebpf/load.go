package ebpf

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/boratanrikulu/durdur/internal/generated"
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
	return generated.LoadBpfObjects(e.Objects, nil)
}

// Attach attachs eBPF program to the kernel.
func (e *EBPF) Attach(iface *net.Interface) error {
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   e.Objects.XdpDurdurDropFunc,
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}
	e.L = l
	return nil
}

// Close cleans the resources.
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

// LoadAndRun loads and attachs the eBPF program.
func LoadAndRun(iface *net.Interface, toIPs, fromIPs []net.IP) error {
	e := New()
	if err := e.Load(); err != nil {
		return fmt.Errorf("load ebpf: %s", err)
	}
	defer e.Objects.Close()

	if err := e.Attach(iface); err != nil {
		return fmt.Errorf("attach ebpf: %s", err)
	}
	defer e.L.Close()

	for _, toIP := range toIPs {
		if err := e.AddToIP(toIP); err != nil {
			return fmt.Errorf("could not insert To ip to the map: %s", err)
		}
	}
	for _, fromIP := range fromIPs {
		if err := e.AddFromIP(fromIP); err != nil {
			return fmt.Errorf("could not insert From ip to the map: %s", err)
		}
	}

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)
	<-termChan

	return nil
}
