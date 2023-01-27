package ebpf

import (
	"errors"
	"fmt"
	"net"
)

var ErrDeleteFromMap = errors.New("could not delete from map")

func (e *EBPF) UndropSrc(srcs ...net.IP) error {
	for _, src := range srcs {
		if err := e.Objects.DropSrcAddrs.Delete(src.To4()); err != nil {
			return fmt.Errorf("delete src-ip: %w: %s", ErrDeleteFromMap, err)
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
		if err := e.Objects.DropDns.Delete(key); err != nil {
			return fmt.Errorf("delete dns: %w: %s", ErrDeleteFromMap, err)
		}
	}

	return nil
}
