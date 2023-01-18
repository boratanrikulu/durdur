package ebpf

import (
	"fmt"
	"net"
)

func (e *EBPF) DropFrom(froms ...net.IP) error {
	for _, from := range froms {
		if err := e.AddFromIP(from); err != nil {
			return fmt.Errorf("add from-ip: %w", err)
		}
	}

	return nil
}

func (e *EBPF) DropTo(tos ...net.IP) error {
	for _, to := range tos {
		if err := e.AddToIP(to); err != nil {
			return fmt.Errorf("add to-ip: %w", err)
		}
	}

	return nil
}

func (e *EBPF) DropDNS(dnss ...string) error {
	for _, dns := range dnss {
		key, err := stringToBytes(dns)
		if err != nil {
			return err
		}
		if err := e.AddDNS(key); err != nil {
			return fmt.Errorf("add dns: %w", err)
		}
	}

	return nil
}
