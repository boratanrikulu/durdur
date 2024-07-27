package ebpf

import (
	"bytes"
	"errors"
	"fmt"
)

var (
	ErrListMap = errors.New("could not list the map")
)

func (e *EBPF) ListSrc() (map[string]int, error) {
	srcList := make(map[string]int)

	entries := e.Objects.DropSrcAddrs.Iterate()
	for {
		var key uint32
		var value int64
		if next := entries.Next(&key, &value); !next {
			break
		}
		srcList[uint32ToNetIP(key).String()] = int(value)

	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrListMap, err)
	}

	return srcList, nil
}

func (e *EBPF) ListDNS() (map[string]int, error) {
	dnsList := make(map[string]int)

	entries := e.Objects.DropDns.Iterate()
	for {
		var key [bytesLength]byte
		var value int64
		if next := entries.Next(&key, &value); !next {
			break
		}
		n := bytes.IndexByte(key[:], 0)
		dnsList[string(key[:n])] = int(value)

	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrListMap, err)
	}

	return dnsList, nil
}
