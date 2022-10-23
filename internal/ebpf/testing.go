package ebpf

import (
	"net"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

var (
	tIface     *net.Interface // It is set by tNew().
	tIfaceStr  = "eth0"
	tFromIP    net.IP // It is set by tNew().
	tFromIPStr = "178.128.201.89"
)

// tNew initializes testing variables and returns *qt.C.
func tNew(t *testing.T) *qt.C {
	c := qt.New(t)

	var err error
	tIface, err = net.InterfaceByName(tIfaceStr)
	if err != nil {
		c.Fatal(err)
	}
	tFromIP = net.ParseIP(tFromIPStr)

	return c
}

// tDoUntil is able to do pre-steps for testings.
// Supported until-steps;
// - attach
// - detach
// - drop-from
// - undrop-from
func tDoUntil(c *qt.C, e *EBPF, until string) {
	switch until {
	case "attach":
		c.Assert(e.Attach(tIface), qt.IsNil)
	case "detach":
		c.Assert(e.Attach(tIface), qt.IsNil)
		c.Assert(e.Detach(), qt.IsNil)
	case "drop-from":
		c.Assert(e.Attach(tIface), qt.IsNil)
		c.Assert(e.AddFromIP(tFromIP), qt.IsNil)
	case "undrop-from":
		c.Assert(e.Attach(tIface), qt.IsNil)
		c.Assert(e.AddFromIP(tFromIP), qt.IsNil)
		c.Assert(e.DeleteFromIP(tFromIP), qt.IsNil)
	default:
		c.Fatalf("%s until type is not supported", until)
	}
}

// tWrappedFunc follows these steps;
//   - makes until-steps
//   - does the job (f())
//   - detaches if it's needed
func tWrappedFunc(c *qt.C, until string, f func(e *EBPF)) {
	e, err := newEBPF()
	c.Assert(err, qt.IsNil)

	if until != "" {
		tDoUntil(c, e, until)
		tWait()
	}

	f(e)

	if until != "detach" {
		tWait()
		if err := e.Detach(); err != nil {
			c.Fatalf("detach resources: %s", err)
		}
	}

	tWait()
}

// tWait waits.
func tWait() {
	time.Sleep(1 * time.Second) // TODO: remove this line.
}
