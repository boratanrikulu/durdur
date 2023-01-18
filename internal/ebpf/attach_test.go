package ebpf

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestAttach(t *testing.T) {
	c := tNew(t)

	c.Run("attach", func(c *qt.C) {
		newTWrap().Run(c, "", func(e *EBPF) {
			c.Assert(e.Attach(tIface), qt.IsNil)
		})
	})

	c.Run("attach, already attached", func(c *qt.C) {
		newTWrap().Run(c, "attach", func(e *EBPF) {
			err := e.Attach(tIface)
			c.Assert(err, qt.IsNotNil)
			c.Assert(err, qt.ErrorIs, ErrAlreadyAttached)
		})
	})
}
