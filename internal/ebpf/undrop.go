package ebpf

import (
	"fmt"
	"net"
)

func (e *EBPF) UndropSrc(srcs ...net.IP) error {
	for _, src := range srcs {
		if err := e.DeleteSrcIP(src); err != nil {
			return fmt.Errorf("delete src-ip: %w", err)
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
