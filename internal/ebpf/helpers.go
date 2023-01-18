package ebpf

import (
	"errors"
	"fmt"
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
