// generated package contains auto compiled eBPF byte code.
// DO NOT EDIT any file under /internal/generated folder.
// Edit /internal/ebpf code to be able to change eBPF source code.
package generated

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS Bpf ../ebpf-c/xdp.c
