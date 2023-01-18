package ebpf

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestDetach(t *testing.T) {
	c := tNew(t)

	c.Run("detach", func(c *qt.C) {
		newTWrap().WithoutClean().Run(c, "attach", func(e *EBPF) {
			c.Assert(e.Detach(), qt.IsNil)
		})
	})

	c.Run("detach, non-attached", func(c *qt.C) {
		e, err := NewEBPF()
		c.Assert(err, qt.IsNil)
		defer e.Close()

		err = e.Detach()
		c.Assert(err, qt.IsNotNil)
		c.Assert(err, qt.ErrorIs, ErrNoAttach)
	})
}
