package ebpf

import (
	"errors"
	"net"
)

var (
	ErrInsertToMap = errors.New("could not insert to map")
)

// Add puts given DST IP to the Map.
func (e *EBPF) AddDstIP(ip net.IP) error {
	if err := e.Objects.DropDstAddrs.Put(ip.To4(), uint64(0)); err != nil {
		return ErrInsertToMap
	}
	return nil
}

// Add puts given SRC IP to the Map.
func (e *EBPF) AddSrcIP(ip net.IP) error {
	if err := e.Objects.DropSrcAddrs.Put(ip.To4(), uint64(0)); err != nil {
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

// DeleteToIP deletes given DST IP from the Map.
func (e *EBPF) DeleteDstIP(ip net.IP) error {
	if err := e.Objects.DropDstAddrs.Delete(ip.To4()); err != nil {
		return ErrInsertToMap
	}
	return nil
}

// DeleteToIP deletes given SRC IP from the Map.
func (e *EBPF) DeleteSrcIP(ip net.IP) error {
	if err := e.Objects.DropSrcAddrs.Delete(ip.To4()); err != nil {
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
