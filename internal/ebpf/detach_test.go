package ebpf

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestDetach(t *testing.T) {
	c := tNew(t)

	t.Run("detach", func(t *testing.T) {
		tWrappedFunc(c, "attach", func(e *EBPF) {
			c.Assert(e.Detach(), qt.IsNil)
		})
	})
}
