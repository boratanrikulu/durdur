package ebpf

import (
	"context"
	"net"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

var (
	tIface    *net.Interface // It is set by tNew().
	tIfaceStr = "eth0"

	tSrcIP    net.IP // It is set by tNew().
	tSrcIpStr = "169.155.49.112"
	tDNS      = "quik.bora.sh"
)

// tNew initializes testing variables and returns *qt.C.
func tNew(t *testing.T) *qt.C {
	c := qt.New(t)

	var err error
	tIface, err = net.InterfaceByName(tIfaceStr)
	if err != nil {
		c.Fatal(err)
	}

	tSrcIP = net.ParseIP(tSrcIpStr)

	return c
}

// tDoUntil is able to do pre-steps for testings.
// Supported until-steps;
// - attach
// - drop-src
// - drop-dns
func tDoUntil(c *qt.C, e *EBPF, until string) {
	switch until {
	case "attach":
		c.Assert(e.Attach(tIface), qt.IsNil)
	case "drop-src":
		c.Assert(e.Attach(tIface), qt.IsNil)
		c.Assert(e.DropSrc(tSrcIP), qt.IsNil)
	case "drop-dns":
		c.Assert(e.Attach(tIface), qt.IsNil)
		c.Assert(e.DropDNS(tDNS), qt.IsNil)
	default:
		c.Fatalf("%s until type is not supported", until)
	}
}

type tWrap struct {
	clean bool
}

func newTWrap() *tWrap {
	return &tWrap{
		clean: true,
	}
}

// WithoutClean disables calling Detach() after running the test.
// Be careful when you disable it, you may break other tests.
func (tw *tWrap) WithoutClean() *tWrap {
	tw.clean = false
	return tw
}

// Run follows these steps;
//   - makes until-steps
//   - runs the job (f())
//   - cleans resources if it's needed
func (tw *tWrap) Run(c *qt.C, until string, f func(e *EBPF)) {
	e, err := NewEBPF()
	c.Assert(err, qt.IsNil)

	if until != "" {
		tDoUntil(c, e, until)
	}

	if tw.clean {
		c.Cleanup(func() {
			c.Assert(e.Detach(), qt.IsNil)
		})
	}

	f(e)
}

// TTCPWrite tests the TCP connection through the address.
func TTCPWrite(c *qt.C, address string, ok bool) {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if !ok {
		c.Assert(err, qt.ErrorMatches, ".* i/o timeout")
		return
	}
	c.Assert(err, qt.IsNil)
	defer conn.Close()

	_, err = conn.Write([]byte("hey"))
	c.Assert(err, qt.IsNil)
}

// TDNSLookup tests if the DNS lookup works well without using DNS cache.
func TDNSLookup(c *qt.C, dns string, ok bool) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, "8.8.8.8:53")
		},
	}

	_, err := r.LookupIP(context.Background(), "ip", dns)
	if !ok {
		c.Assert(err, qt.IsNotNil)
		return
	}
	c.Assert(err, qt.IsNil)
}
