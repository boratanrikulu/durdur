package ebpf

import (
	"fmt"
	"net"
)

// Undrop deletes IPs from the maps.
func Undrop(toIPs, fromIPs []net.IP) error {
	e, err := newEBPFWithLink()
	if err != nil {
		return err
	}
	defer e.Close()

	for _, toIP := range toIPs {
		if err := e.DeleteToIP(toIP); err != nil {
			return fmt.Errorf("could not delete TO IP to the map: %w", err)
		}
	}

	for _, fromIP := range fromIPs {
		if err := e.DeleteFromIP(fromIP); err != nil {
			return fmt.Errorf("could not delete FROM IP to the map: %w", err)
		}
	}

	return nil
}
