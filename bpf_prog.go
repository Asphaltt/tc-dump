// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func getEntryFuncName(prog *ebpf.Program) (string, error) {
	info, err := prog.Info()
	if err != nil {
		return "", fmt.Errorf("failed to get program info: %w", err)
	}

	id, ok := info.BTFID()
	if !ok {
		return "", fmt.Errorf("bpf program %s does not have BTF", info.Name)
	}

	handle, err := btf.NewHandleFromID(id)
	if err != nil {
		return "", fmt.Errorf("failed to get BTF handle: %w", err)
	}
	defer handle.Close()

	spec, err := handle.Spec(nil)
	if err != nil {
		return "", fmt.Errorf("failed to get BTF spec: %w", err)
	}

	iter := spec.Iterate()
	for iter.Next() {
		if fn, ok := iter.Type.(*btf.Func); ok {
			return fn.Name, nil
		}
	}

	return "", fmt.Errorf("no function found in %s bpf prog", info.Name)
}
