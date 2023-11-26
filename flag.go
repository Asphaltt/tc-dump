package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

type flags struct {
	Devices []string

	FilterMark uint32

	KeepTcQdisc bool

	PcapFilterExpr string
}

func parseFlags() *flags {
	var f flags

	flag.StringSliceVarP(&f.Devices, "device", "d", nil, "network devices to run tc-dump")
	flag.Uint32VarP(&f.FilterMark, "filter-mark", "m", 0, "filter mark for tc-dump")

	flag.BoolVarP(&f.KeepTcQdisc, "keep-tc-qdisc", "k", false, "keep tc-qdisc when exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [pcap-filter]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    Available pcap-filter: see \"man 7 pcap-filter\"\n")
		fmt.Fprintf(os.Stderr, "    Available options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	f.PcapFilterExpr = strings.Join(flag.Args(), " ")

	return &f
}

func (f *flags) getDevices() map[int]string {
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatalf("Failed to list links: %v", err)
	}

	m := make(map[int]string)
	if len(f.Devices) == 0 {
		for _, l := range links {
			ifindex, ifname := l.Attrs().Index, l.Attrs().Name
			m[ifindex] = ifname
		}

		return m
	}

	target := make(map[string]struct{}, len(f.Devices))
	for _, dev := range f.Devices {
		target[dev] = struct{}{}
	}
	for _, l := range links {
		ifindex, ifname := l.Attrs().Index, l.Attrs().Name
		if _, ok := target[ifname]; ok {
			m[ifindex] = ifname
		}
	}

	return m
}
