package ebpf

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestLoad(t *testing.T) {
	c := tNew(t)

	e, err := NewEBPF()
	c.Assert(err, qt.IsNil)
	c.Assert(e.Close(), qt.IsNil)

	newTWrap().Run(c, "attach", func(_ *EBPF) {
		e, err := NewEBPFWithLink()
		c.Assert(err, qt.IsNil)
		c.Assert(e.Close(), qt.IsNil)
	})
}
