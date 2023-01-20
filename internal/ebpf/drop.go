package ebpf

import (
	"fmt"
	"net"
)

func (e *EBPF) DropSrc(srcs ...net.IP) error {
	for _, src := range srcs {
		if err := e.AddSrcIP(src); err != nil {
			return fmt.Errorf("add src-ip: %w", err)
		}
	}

	return nil
}

func (e *EBPF) DropDst(dsts ...net.IP) error {
	for _, dst := range dsts {
		if err := e.AddDstIP(dst); err != nil {
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
