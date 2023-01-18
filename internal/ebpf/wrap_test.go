package ebpf

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestWrapForAttached(t *testing.T) {
	c := tNew(t)

	newTWrap().Run(c, "attach", func(e *EBPF) {
		c.Assert(WrapForAttached(func(e *EBPF) error {
			return e.Detach()
		}), qt.IsNil)
	})
}

func TestWrapForDetached(t *testing.T) {
	c := tNew(t)

	c.Assert(WrapForDetached(func(e *EBPF) error {
		if err := e.Attach(tIface); err != nil {
			return err
		}
		return e.Detach()
	}), qt.IsNil)
}
