package ebpf

import (
	"fmt"
	"net"
)

func (e *EBPF) UndropFrom(froms ...net.IP) error {
	for _, from := range froms {
		if err := e.DeleteFromIP(from); err != nil {
			return fmt.Errorf("delete from-ip: %w", err)
		}
	}

	return nil
}

func (e *EBPF) UndropTo(tos ...net.IP) error {
	for _, to := range tos {
		if err := e.DeleteToIP(to); err != nil {
			return fmt.Errorf("delete to-ip: %w", err)
		}
	}

	return nil
}

func (e *EBPF) UndropDNS(dnss ...string) error {
	for _, dns := range dnss {
		key, err := stringToBytes(dns)
		if err != nil {
			return err
		}
		if err := e.DeleteDNS(key); err != nil {
			return fmt.Errorf("delete dns: %w", err)
		}
	}

	return nil
}
