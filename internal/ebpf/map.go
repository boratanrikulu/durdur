package ebpf

import (
	"net"
)

// Add puts given TO IP to the Map.
func (e *EBPF) AddToIP(ip net.IP) error {
	return e.Objects.DropToAddrs.Put(ip.To4(), uint64(0))
}

// Add puts given FROM IP to the Map.
func (e *EBPF) AddFromIP(ip net.IP) error {
	return e.Objects.DropFromAddrs.Put(ip.To4(), uint64(0))
}
