package ebpf

import (
	"fmt"
	"net"
)

func (e *EBPF) UndropSrc(froms ...net.IP) error {
	for _, from := range froms {
		if err := e.DeleteSrcIP(from); err != nil {
			return fmt.Errorf("delete src-ip: %w", err)
		}
	}

	return nil
}

func (e *EBPF) UndropDst(tos ...net.IP) error {
	for _, to := range tos {
		if err := e.DeleteDstIP(to); err != nil {
			return fmt.Errorf("delete dst-ip: %w", err)
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
