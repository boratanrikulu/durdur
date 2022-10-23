package ebpf

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestLoad(t *testing.T) {
	c := tNew(t)

	e, err := newEBPF()
	c.Assert(err, qt.IsNil)
	c.Assert(e.Close(), qt.IsNil)

	tWrappedFunc(c, "attach", func(_ *EBPF) {
		e, err := newEBPFWithLink()
		c.Assert(err, qt.IsNil)
		c.Assert(e.Close(), qt.IsNil)
	})
}
