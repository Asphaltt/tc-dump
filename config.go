package main

import (
	"unsafe"
)

type config struct {
	Mark uint32
}

const _ = int(unsafe.Sizeof(config{}))

func newConfig(flags *flags) *config {
	var cfg config

	cfg.Mark = flags.FilterMark

	return &cfg
}
