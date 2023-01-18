package ebpf

import (
	"errors"
	"net"
)

var (
	ErrInsertToMap = errors.New("could not insert to map")
)

// Add puts given TO IP to the Map.
func (e *EBPF) AddToIP(ip net.IP) error {
	if err := e.Objects.DropToAddrs.Put(ip.To4(), uint64(0)); err != nil {
		return ErrInsertToMap
	}
	return nil
}

// Add puts given FROM IP to the Map.
func (e *EBPF) AddFromIP(ip net.IP) error {
	if err := e.Objects.DropFromAddrs.Put(ip.To4(), uint64(0)); err != nil {
		return ErrInsertToMap
	}
	return nil
}

// Add puts given DNS to the Map.
func (e *EBPF) AddDNS(dns [bytesLength]byte) error {
	if err := e.Objects.DropDns.Put(dns, uint64(0)); err != nil {
		return ErrInsertToMap
	}
	return nil
}

// DeleteToIP deletes given TO IP from the Map.
func (e *EBPF) DeleteToIP(ip net.IP) error {
	if err := e.Objects.DropToAddrs.Delete(ip.To4()); err != nil {
		return ErrInsertToMap
	}
	return nil
}

// DeleteToIP deletes given FROM IP from the Map.
func (e *EBPF) DeleteFromIP(ip net.IP) error {
	if err := e.Objects.DropFromAddrs.Delete(ip.To4()); err != nil {
		return ErrInsertToMap
	}
	return nil
}

// DeleteDNS deletes given DNS from the Map.
func (e *EBPF) DeleteDNS(dns [bytesLength]byte) error {
	if err := e.Objects.DropDns.Delete(dns); err != nil {
		return ErrInsertToMap
	}
	return nil
}
