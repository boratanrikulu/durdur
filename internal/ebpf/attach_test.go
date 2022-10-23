package ebpf

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestAttach(t *testing.T) {
	c := tNew(t)

	t.Run("attach", func(t *testing.T) {
		tWrappedFunc(c, "", func(e *EBPF) {
			c.Assert(e.Attach(tIface), qt.IsNil)
		})
	})
}
