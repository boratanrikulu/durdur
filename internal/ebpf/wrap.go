package ebpf

func WrapForAttached(f func(e *EBPF) error) error {
	e, err := NewEBPFWithLink()
	if err != nil {
		return err
	}
	defer e.Close()

	return f(e)
}

func WrapForDetached(f func(e *EBPF) error) error {
	e, err := NewEBPF()
	if err != nil {
		return err
	}
	defer e.Close()

	return f(e)
}
