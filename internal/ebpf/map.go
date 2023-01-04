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

// Add puts given DNS to the Map.
func (e *EBPF) AddDNS(dns string) error {
	key, err := stringToBytes(dns)
	if err != nil {
		return err
	}
	return e.Objects.DropDns.Put(key, uint64(0))
}

// DeleteToIP deletes given TO IP from the Map.
func (e *EBPF) DeleteToIP(ip net.IP) error {
	return e.Objects.DropToAddrs.Delete(ip.To4())
}

// DeleteToIP deletes given FROM IP from the Map.
func (e *EBPF) DeleteFromIP(ip net.IP) error {
	return e.Objects.DropFromAddrs.Delete(ip.To4())
}

// DeleteDNS deletes given DNS from the Map.
func (e *EBPF) DeleteDNS(dns string) error {
	key, err := stringToBytes(dns)
	if err != nil {
		return err
	}
	return e.Objects.DropDns.Delete(key)
}
