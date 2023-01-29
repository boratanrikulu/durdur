package ebpf

import (
	"errors"
	"fmt"
	"net"
)

var (
	ErrInvalidUsage = errors.New("invalid usage")
)

const bytesLength = 128

func stringToBytes(input string) ([bytesLength]byte, error) {
	output := [bytesLength]byte{}
	bs := []byte(input)
	if len(bs) > bytesLength {
		return output, fmt.Errorf("%s is longer than %d characters: %w", input, bytesLength, ErrInvalidUsage)
	}
	copy(output[:], bs)
	return output, nil
}

func uint32ToNetIP(val uint32) net.IP {
	return net.IPv4(byte(val&0xFF), byte(val>>8)&0xFF, byte(val>>16&0xFF), byte(val>>24))
}
