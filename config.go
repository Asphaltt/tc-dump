package main

import (
	"log"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

type config struct {
	VlanID   uint16
	VxlanVNI uint32

	Mark uint32

	Saddr uint32
	Daddr uint32
	Addr  uint32
	Sport uint16
	Dport uint16
	Port  uint16

	L4Proto uint8
	Pad     [3]uint8
}

const _ = int(unsafe.Sizeof(config{}))

func newConfig(flags *flags) *config {
	var cfg config

	cfg.VlanID = flags.FilterVlanID
	cfg.VxlanVNI = flags.FilterVxlanVNI

	cfg.Mark = flags.FilterMark

	cfg.Saddr = parseIP(flags.FilterSaddr)
	cfg.Daddr = parseIP(flags.FilterDaddr)
	cfg.Addr = parseIP(flags.FilterAddr)

	cfg.Sport = htons(flags.FilterSport)
	cfg.Dport = htons(flags.FilterDport)
	cfg.Port = htons(flags.FilterPort)

	switch proto := strings.ToUpper(flags.FilterProto); proto {
	case "TCP":
		cfg.L4Proto = unix.IPPROTO_TCP
	case "UDP":
		cfg.L4Proto = unix.IPPROTO_UDP
	case "ICMP":
		cfg.L4Proto = unix.IPPROTO_ICMP
	case "":
	default:
		log.Fatalf("Unsupport filter-proto %s", proto)
	}

	return &cfg
}

func parseIP(s string) uint32 {
	if s == "" {
		return 0
	}

	ip4 := net.ParseIP(s).To4()
	if ip4 == nil {
		log.Fatalf("%s is not a valid IPv4 address", s)
	}

	return *(*uint32)(unsafe.Pointer(&ip4[0]))
}
