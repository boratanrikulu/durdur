package ebpf

import (
	"fmt"
)

// newEBPF returns a new loaded EBPF.
func newEBPF() (*EBPF, error) {
	e := New()
	if err := e.Load(); err != nil {
		return nil, err
	}

	return e, nil
}

// newEBPFWithLink returns a new loaded EBPF by loading the link.
func newEBPFWithLink() (*EBPF, error) {
	e, err := newEBPF()
	if err != nil {
		return nil, err
	}

	if err := e.LoadAttachedLink(); err != nil {
		return nil, err
	}

	return e, nil
}

const bytesLength = 128

func stringToBytes(input string) ([bytesLength]byte, error) {
	output := [bytesLength]byte{}
	bs := []byte(input)
	if len(bs) > bytesLength {
		return output, fmt.Errorf("%s is longer than %d characters", input, bytesLength)
	}
	copy(output[:], bs)
	return output, nil
}
