package ebpf

import (
	"fmt"
	"net"
)

// Drop add new rules to the maps.
func Drop(toIPs, fromIPs []net.IP, dnss []string) error {
	e, err := newEBPFWithLink()
	if err != nil {
		return err
	}
	defer e.Close()

	for _, toIP := range toIPs {
		if err := e.AddToIP(toIP); err != nil {
			return fmt.Errorf("could not insert TO IP to the map: %w", err)
		}
	}

	for _, fromIP := range fromIPs {
		if err := e.AddFromIP(fromIP); err != nil {
			return fmt.Errorf("could not insert FROM IP to the map: %w", err)
		}
	}

	for _, dns := range dnss {
		if err := e.AddDNS(dns); err != nil {
			return fmt.Errorf("could not insert DNS to the map: %w", err)
		}
	}

	return nil
}
