package ebpf

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestNew(t *testing.T) {
	c := tNew(t)

	c.Run("new eBPF when the program is attached", func(c *qt.C) {
		newTWrap().Run(c, "attach", func(_ *EBPF) {
			e, err := NewEBPFWithLink()
			c.Assert(err, qt.IsNil)
			c.Assert(e.Close(), qt.IsNil)
		})
	})

	c.Run("new eBPF when the program is not attached", func(c *qt.C) {
		e, err := NewEBPF()
		c.Assert(err, qt.IsNil)
		c.Assert(e.Close(), qt.IsNil)

		_, err = NewEBPFWithLink()
		c.Assert(err, qt.IsNotNil)
		c.Assert(err, qt.ErrorIs, ErrNoAttach)
	})
}
