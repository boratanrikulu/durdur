package ebpf

import (
	"fmt"
	"net"
)

func (e *EBPF) DropSrc(froms ...net.IP) error {
	for _, from := range froms {
		if err := e.AddSrcIP(from); err != nil {
			return fmt.Errorf("add src-ip: %w", err)
		}
	}

	return nil
}

func (e *EBPF) DropDst(tos ...net.IP) error {
	for _, to := range tos {
		if err := e.AddDstIP(to); err != nil {
			return fmt.Errorf("add dst-ip: %w", err)
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
