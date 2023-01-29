package ebpf

import (
	"errors"
	"fmt"
	"net"
)

var ErrInsertToMap = errors.New("could not insert to map")

func (e *EBPF) DropSrc(srcs ...net.IP) error {
	for _, src := range srcs {
		if err := e.Objects.DropSrcAddrs.Put(src.To4(), uint64(0)); err != nil {
			return fmt.Errorf("add src-ip: %w: %s", ErrInsertToMap, err)
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
		if err := e.Objects.DropDns.Put(key, uint64(0)); err != nil {
			return fmt.Errorf("add dns: %w: %s", ErrInsertToMap, err)
		}
	}

	return nil
}
